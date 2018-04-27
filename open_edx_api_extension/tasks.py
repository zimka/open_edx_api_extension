import json
import logging
from datetime import datetime
from functools import partial
from time import time

from celery import task
from certificates.models import CertificateWhitelist, certificate_info_for_user
from django.conf import settings
from pytz import UTC
from student.models import UserProfile
from xmodule.split_test_module import get_split_user_partitions

from courseware.grades import iterate_grades_for
from courseware.courses import get_course_by_id
from instructor_task.api_helper import submit_task
from instructor_task.models import ReportStore
from instructor_task.tasks_helper import BaseInstructorTask, run_main_task, upload_csv_to_report_store, LmsPartitionService, CourseEnrollment
from instructor_task.tasks_helper import TaskProgress, CourseTeamMembership, SoftwareSecurePhotoVerification
#from verify_student.models import SoftwareSecurePhotoVerification
from openedx.core.djangoapps.course_groups.cohorts import is_course_cohorted, get_cohort


TASK_LOG = logging.getLogger('edx.celery.task')


def kns_submit_calculate_grades_csv(request, course_key):
    """
    AlreadyRunningError is raised if the course's grades are already being updated.
    """
    task_type = 'grade_course_kns'
    task_class = kns_calculate_grades_csv_task_for_users
    task_input = {}
    task_key = ""

    return submit_task(request, task_type, task_class, course_key, task_input, task_key)


@task(base=BaseInstructorTask, routing_key=settings.GRADES_DOWNLOAD_ROUTING_KEY)  # pylint: disable=not-callable
def kns_calculate_grades_csv_task_for_users(entry_id, xmodule_instance_args):
    """
    Grade a course and push results to ReportStorage and PLP.
    """
    action_name = 'graded'
    TASK_LOG.info(
        u"Task: %s, InstructorTask ID: %s, Task type: %s, Preparing for task execution",
        xmodule_instance_args.get('task_id'), entry_id, action_name
    )

    task_fn = partial(kns_upload_grades_csv, xmodule_instance_args)
    return run_main_task(entry_id, task_fn, action_name)


def kns_upload_grades_csv(_xmodule_instance_args, _entry_id, course_id, _task_input, action_name):  # pylint: disable=too-many-statements
    """
    For a given `course_id`, generate a grades CSV file for all students that
    are enrolled, and store using a `ReportStore`. Once created, the files can
    be accessed by instantiating another `ReportStore` (via
    `ReportStore.from_config()`) and calling `link_for()` on it. Writes are
    buffered, so we'll never write part of a CSV file to S3 -- i.e. any files
    that are visible in ReportStore will be complete ones.

    As we start to add more CSV downloads, it will probably be worthwhile to
    make a more general CSVDoc class instead of building out the rows like we
    do here.
    """
    def get_extended_info(student):
        info = []
        info.append(CourseEnrollment.get_enrollment(student, course_id).id)
        profile = UserProfile.objects.get(user=student)
        try:
            goals = json.loads(profile.goals)
            info.append(goals.get("kns_id"))
            return info
        except ValueError as e:
            pass
        except Exception as e:
            logging.error("upload_kns_grades_csv error with .goals '{}':'{}'".format(str(profile.goals), str(e)))
        info.append(None)
        return info

    extended_fields = ["enr_id", "kns_id"]
    override_name = "EXTENDED_GRADES_DOWNLOAD"
    extended_config_name = override_name if hasattr(settings, override_name) else 'GRADES_DOWNLOAD'

    start_time = time()
    start_date = datetime.now(UTC)
    status_interval = 100
    enrolled_students = CourseEnrollment.objects.users_enrolled_in(course_id)
    task_progress = TaskProgress(action_name, enrolled_students.count(), start_time)

    fmt = u'Task: {task_id}, InstructorTask ID: {entry_id}, Course: {course_id}, Input: {task_input}'
    task_info_string = fmt.format(
        task_id=_xmodule_instance_args.get('task_id') if _xmodule_instance_args is not None else None,
        entry_id=_entry_id,
        course_id=course_id,
        task_input=_task_input
    )
    TASK_LOG.info(u'%s, Task type: %s, Starting task execution', task_info_string, action_name)

    course = get_course_by_id(course_id)
    course_is_cohorted = is_course_cohorted(course.id)
    teams_enabled = course.teams_enabled
    cohorts_header = ['Cohort Name'] if course_is_cohorted else []
    teams_header = ['Team Name'] if teams_enabled else []

    experiment_partitions = get_split_user_partitions(course.user_partitions)
    group_configs_header = [u'Experiment Group ({})'.format(partition.name) for partition in experiment_partitions]

    certificate_info_header = ['Certificate Eligible', 'Certificate Delivered', 'Certificate Type']
    certificate_whitelist = CertificateWhitelist.objects.filter(course_id=course_id, whitelist=True)
    whitelisted_user_ids = [entry.user_id for entry in certificate_whitelist]

    # Loop over all our students and build our CSV lists in memory
    header = None
    rows = []
    err_rows = [["id", "username", "error_msg"]]
    current_step = {'step': 'Calculating Grades'}

    total_enrolled_students = enrolled_students.count()
    student_counter = 0
    TASK_LOG.info(
        u'%s, Task type: %s, Current step: %s, Starting grade calculation for total students: %s',
        task_info_string,
        action_name,
        current_step,

        total_enrolled_students
    )
    for student, gradeset, err_msg in iterate_grades_for(course_id, enrolled_students):
        # Periodically update task status (this is a cache write)
        if task_progress.attempted % status_interval == 0:
            task_progress.update_task_state(extra_meta=current_step)
        task_progress.attempted += 1

        # Now add a log entry after each student is graded to get a sense
        # of the task's progress
        student_counter += 1
        TASK_LOG.info(
            u'%s, Task type: %s, Current step: %s, Grade calculation in-progress for students: %s/%s',
            task_info_string,
            action_name,
            current_step,
            student_counter,
            total_enrolled_students
        )

        if gradeset:
            # We were able to successfully grade this student for this course.
            task_progress.succeeded += 1
            if not header:
                header = [section['label'] for section in gradeset[u'section_breakdown']]
                rows.append(
                    ["id", "email", "username", "grade"] + header + cohorts_header +
                    group_configs_header + teams_header +
                    ['Enrollment Track', 'Verification Status'] + certificate_info_header + extended_fields
                )

            percents = {
                section['label']: section.get('percent', 0.0)
                for section in gradeset[u'section_breakdown']
                if 'label' in section
            }

            cohorts_group_name = []
            if course_is_cohorted:
                group = get_cohort(student, course_id, assign=False)
                cohorts_group_name.append(group.name if group else '')

            group_configs_group_names = []
            for partition in experiment_partitions:
                group = LmsPartitionService(student, course_id).get_group(partition, assign=False)
                group_configs_group_names.append(group.name if group else '')

            team_name = []
            if teams_enabled:
                try:
                    membership = CourseTeamMembership.objects.get(user=student, team__course_id=course_id)
                    team_name.append(membership.team.name)
                except CourseTeamMembership.DoesNotExist:
                    team_name.append('')

            enrollment_mode = CourseEnrollment.enrollment_mode_for_user(student, course_id)[0]
            verification_status = SoftwareSecurePhotoVerification.verification_status_for_user(
                student,
                course_id,
                enrollment_mode
            )
            certificate_info = certificate_info_for_user(
                student,
                course_id,
                gradeset['grade'],
                student.id in whitelisted_user_ids
            )

            # Not everybody has the same gradable items. If the item is not
            # found in the user's gradeset, just assume it's a 0. The aggregated
            # grades for their sections and overall course will be calculated
            # without regard for the item they didn't have access to, so it's
            # possible for a student to have a 0.0 show up in their row but
            # still have 100% for the course.
            row_percents = [percents.get(label, 0.0) for label in header]
            additional_info = get_extended_info(student)
            rows.append(
                [student.id, student.email, student.username, gradeset['percent']] +
                row_percents + cohorts_group_name + group_configs_group_names + team_name +
                [enrollment_mode] + [verification_status] + certificate_info + additional_info
            )
        else:
            # An empty gradeset means we failed to grade a student.
            task_progress.failed += 1
            err_rows.append([student.id, student.username, err_msg])

    TASK_LOG.info(
        u'%s, Task type: %s, Current step: %s, Grade calculation completed for students: %s/%s',
        task_info_string,
        action_name,
        current_step,
        student_counter,
        total_enrolled_students
    )

    # By this point, we've got the rows we're going to stuff into our CSV files.
    current_step = {'step': 'Uploading CSVs'}
    task_progress.update_task_state(extra_meta=current_step)
    TASK_LOG.info(u'%s, Task type: %s, Current step: %s', task_info_string, action_name, current_step)

    start_date = start_date.replace(hour=0, minute=0)
    # Perform the actual upload
    upload_csv_to_report_store(rows, 'extended_grade_report', course_id, start_date, config_name=extended_config_name)

    # If there are any error rows (don't count the header), write them out as well
    if len(err_rows) > 1:
        upload_csv_to_report_store(err_rows, 'extended_grade_report_err', course_id, start_date, config_name=extended_config_name)

    # One last update before we close out...
    TASK_LOG.info(u'%s, Task type: %s, Finalizing grade task', task_info_string, action_name)
    return task_progress.update_task_state(extra_meta=current_step)
