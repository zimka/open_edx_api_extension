import logging
from functools import partial
from celery import task
from django.conf import settings
from lms.djangoapps.instructor_task.api_helper import submit_task
from .models import InstructorTaskExtendedKwargs
from .edx_release import BaseInstructorTask, run_main_task, upload_user_grades_csv

TASK_LOG = logging.getLogger('edx.celery.task')


@task(base=BaseInstructorTask, routing_key=settings.GRADES_DOWNLOAD_ROUTING_KEY)  # pylint: disable=not-callable
def calculate_grades_csv_task_for_users(entry_id, xmodule_instance_args):
    """
    Grade a course and push results to ReportStorage and PLP.
    """
    action_name = 'graded'
    TASK_LOG.info(
        u"Task: %s, InstructorTask ID: %s, Task type: %s, Preparing for task execution",
        xmodule_instance_args.get('task_id'), entry_id, action_name
    )

    task_fn = partial(upload_user_grades_csv, xmodule_instance_args)
    return run_main_task(entry_id, task_fn, action_name)


def submit_calculate_grades_csv_users(request, course_key, usernames, callback_url):
    """
    AlreadyRunningError is raised if the course's grades are already being updated.
    """
    task_type = 'grade_users'
    task_class = calculate_grades_csv_task_for_users
    extended_kwargs_id = InstructorTaskExtendedKwargs.get_id_for_kwargs({"usernames": usernames})

    task_input = {
        "requester_id": str(request.user.id),
        "extended_kwargs_id": str(extended_kwargs_id),
        "callback_url": str(callback_url)
    }
    task_key = ""

    return submit_task(request, task_type, task_class, course_key, task_input, task_key)


