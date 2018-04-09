import json
import logging
import random
from datetime import datetime
from functools import partial
from itertools import chain
from time import time

from celery import task
from django.conf import settings
from django.contrib.auth.models import User
from pytz import UTC

from student.models import CourseEnrollment, UserProfile
from xmodule.partitions.partitions_service import PartitionService
from xmodule.split_test_module import get_split_user_partitions

from lms.djangoapps.courseware.courses import get_course_by_id
from lms.djangoapps.certificates.models import CertificateWhitelist, certificate_info_for_user
from lms.djangoapps.grades.new.course_grade_factory import CourseGradeFactory
from lms.djangoapps.instructor_task.models import ReportStore
from lms.djangoapps.instructor_task.tasks_base import BaseInstructorTask
from lms.djangoapps.instructor_task.tasks_helper.runner import run_main_task, TaskProgress
from lms.djangoapps.instructor_task.tasks_helper.utils import upload_csv_to_report_store
from lms.djangoapps.teams.models import CourseTeamMembership
from lms.djangoapps.verify_student.models import SoftwareSecurePhotoVerification
from openedx.core.djangoapps.course_groups.cohorts import is_course_cohorted, get_cohort


from .utils import get_custom_grade_config
from .models import InstructorTaskExtendedKwargs
from .api_client import PlpApiClient


def upload_user_grades_csv(_xmodule_instance_args, _entry_id, course_id, _task_input, action_name):  # pylint: disable=too-many-statements
    """
    For a given `course_id`, for given usernames generates a grades CSV file,
    and store using a `ReportStore`. Once created, the files can
    be accessed by instantiating another `ReportStore` (via
    `ReportStore.from_config()`) and calling `link_for()` on it.

    Unenrolled users and unknown usernames are stored in *_err_*.csv
    This task is very close to the .upload_grades_csv from instructor_tasks.task_helper
    The difference is that we filter enrolled students against requested usernames and
    we push info about this into PLP
    """
    start_time = time()
    start_date = datetime.now(UTC)
    status_interval = 100
    fmt = u'Task: {task_id}, InstructorTask ID: {entry_id}, Course: {course_id}, Input: {task_input}'
    task_info_string = fmt.format(
        task_id=_xmodule_instance_args.get('task_id') if _xmodule_instance_args is not None else None,
        entry_id=_entry_id,
        course_id=course_id,
        task_input=_task_input
    )
    TASK_LOG.info(u'%s, Task type: %s, Starting task execution', task_info_string, action_name)

    extended_kwargs_id = _task_input.get("extended_kwargs_id")
    extended_kwargs = InstructorTaskExtendedKwargs.get_kwargs_for_id(extended_kwargs_id)
    usernames = extended_kwargs.get("usernames", None)

    err_rows = [["id", "username", "error_msg"]]
    if usernames is None:
        message = "Error occured during edx task execution: no usersnames in InstructorTaskExtendedKwargs."
        TASK_LOG.error(u'%s, Task type: %s, ' + message, task_info_string)
        err_rows.append(["-1", "__", message])
        usernames = []

    enrolled_students = CourseEnrollment.objects.users_enrolled_in(course_id)
    enrolled_students = enrolled_students.filter(username__in=usernames)
    total_enrolled_students = enrolled_students.count()
    requester_id = _task_input.get("requester_id")
    task_progress = TaskProgress(action_name, total_enrolled_students, start_time)

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
    rows = []
    current_step = {'step': 'Calculating Grades'}

    TASK_LOG.info(
        u'%s, Task type: %s, Current step: %s, Starting grade calculation for total students: %s',
        task_info_string,
        action_name,
        current_step,
        total_enrolled_students,
    )
    found_students = User.objects.filter(username__in=usernames)
    # Check invalid usernames
    if len(found_students)!= len(usernames):
        found_students_usernames = [x.username for x in found_students]
        for u in usernames:
            if u not in found_students_usernames:
                err_rows.append([-1, u, "invalid_username"])
    # Check not enrolled requested students
    if found_students != enrolled_students:
        diff = found_students.exclude(id__in=enrolled_students)
        for u in diff:
            if u in diff:
                err_rows.append([u.id, u.username, "enrollment_for_username_not_found"])

    total_enrolled_students = enrolled_students.count()
    student_counter = 0
    TASK_LOG.info(
        u'%s, Task type: %s, Current step: %s, Starting grade calculation for total students: %s',
        task_info_string,
        action_name,
        current_step,

        total_enrolled_students
    )

    graded_assignments = course.grading.graded_assignments(course_id)
    grade_header = course.grading.grade_header(graded_assignments)

    rows.append(
        ["Student ID", "Email", "Username", "Last Name", "First Name", "Second Name", "Grade", "Grade Percent"] +
        grade_header +
        cohorts_header +
        group_configs_header +
        teams_header +
        ['Enrollment Track', 'Verification Status'] +
        certificate_info_header
    )
    for student, course_grade, err_msg in CourseGradeFactory().iter(course, enrolled_students):
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

        if not course_grade:
            # An empty course_grade means we failed to grade a student.
            task_progress.failed += 1
            err_rows.append([student.id, student.username, err_msg])
            continue

        # We were able to successfully grade this student for this course.
        task_progress.succeeded += 1

        cohorts_group_name = []
        if course_is_cohorted:
            group = get_cohort(student, course_id, assign=False)
            cohorts_group_name.append(group.name if group else '')

        group_configs_group_names = []
        for partition in experiment_partitions:
            group = PartitionService(course_id).get_group(student, partition, assign=False)
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
            course_grade.letter_grade,
            student.id in whitelisted_user_ids
        )
        second_name = ''
        try:
            up = UserProfile.objects.get(user=student)
            if up.goals:
                second_name = json.loads(up.goals).get('second_name', '')
        except ValueError:
            pass
        if certificate_info[0] == 'Y':
            TASK_LOG.info(
                u'Student is marked eligible_for_certificate'
                u'(user=%s, course_id=%s, grade_percent=%s gradecutoffs=%s, allow_certificate=%s, is_whitelisted=%s)',
                student,
                course_id,
                course_grade.percent,
                course.grade_cutoffs,
                student.profile.allow_certificate,
                student.id in whitelisted_user_ids
            )

        grade_results = course.grading.grade_results(graded_assignments, course_grade)

        grade_results = list(chain.from_iterable(grade_results))

        rows.append(
            [student.id, student.email, student.username, student.last_name, student.first_name,
             second_name, course_grade.percent, course_grade.percent*100] +
            grade_results + cohorts_group_name + group_configs_group_names + team_name +
            [enrollment_mode] + [verification_status] + certificate_info
        )
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

    # Perform the actual upload
    custom_grades_download = get_custom_grade_config()

    report_hash_unique_hash = hex(random.getrandbits(32))[2:]
    report_name = 'plp_grade_users_report_{}_id_{}'.format(report_hash_unique_hash, requester_id)
    err_report_name = 'plp_grade_users_report_err_{}_id_{}'.format(report_hash_unique_hash, requester_id)
    upload_csv_to_report_store(rows, report_name, course_id, start_date, config_name=custom_grades_download)

    # If there are any error rows (don't count the header), write them out as well
    has_errors = len(err_rows) > 1
    if has_errors:
        upload_csv_to_report_store(err_rows, err_report_name, course_id, start_date, config_name=custom_grades_download)

    callback_url = _task_input.get("callback_url", None)

    if callback_url:
        report_store = ReportStore.from_config(config_name=custom_grades_download)
        files_urls_pairs = report_store.links_for(course_id)
        find_by_name = lambda name: [url for filename, url in files_urls_pairs if name in filename][0]
        try:
            csv_url = find_by_name(report_name)
            csv_err_url = find_by_name(err_report_name) if has_errors else None
            PlpApiClient().push_grade_api_result(callback_url, csv_url, csv_err_url)
        except Exception as e:
            TASK_LOG.error("Failed push to PLP:{}".format(str(e)))

    # One last update before we close out...
    TASK_LOG.info(u'%s, Task type: %s, Finalizing grade task', task_info_string, action_name)
    return task_progress.update_task_state(extra_meta=current_step)