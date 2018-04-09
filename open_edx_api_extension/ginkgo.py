import logging
from lms.djangoapps.instructor_task.tasks_helper.grades import CourseGradeReport, _CourseGradeReportContext, datetime, upload_csv_to_report_store, UTC
from lms.djangoapps.instructor_task.models import ReportStore
from xmodule.modulestore.django import modulestore
from .models import InstructorTaskExtendedKwargs
from .api_client import PlpApiClient


class UsersCourseGradeReport(CourseGradeReport):
    REPORT_NAME_TEMPLATE = "user_course_grade_report_{task_id}"
    ERR_REPORT_NAME_TEMPLATE = "user_course_grade_report_err_{task_id}"

    @classmethod
    def generate(cls, _xmodule_instance_args, _entry_id, course_id, _task_input, action_name):
        """
        Public method to generate a grade report.
        """
        extended_kwargs_id = _task_input.get("extended_kwargs_id")
        callback_url = _task_input.get('callback_url')
        extended_kwargs = InstructorTaskExtendedKwargs.get_kwargs_for_id(extended_kwargs_id)
        usernames = extended_kwargs.get("usernames", None)

        with modulestore().bulk_operations(course_id):
            context = _CourseGradeReportContext(_xmodule_instance_args, _entry_id, course_id, _task_input, action_name)
            context.usernames = usernames
            context.callback_url = callback_url
            context.task_id = extended_kwargs_id
            report = UsersCourseGradeReport()
            report._generate(context)
            report.push_results(context)

    def _batched_rows(self, context):
        """
        A generator of batches of (success_rows, error_rows) for this report.
        """
        needed_usernames = set(context.usernames)

        for users in self._batch_users(context):
            users = filter(lambda u: u is not None, users)
            users = filter(lambda u: u.username in needed_usernames, users)
            needed_usernames -= set([u.username for u in users])
            yield self._rows_for_users(context, users)
        if needed_usernames:
            yield [], self._error_rows_not_found(needed_usernames)

    def _upload(self, context, success_headers, success_rows, error_headers, error_rows):
        """
        Creates and uploads a CSV for the given headers and rows.
        """
        date = datetime.now(UTC)

        upload_csv_to_report_store(
            [success_headers] + success_rows,
            self.REPORT_NAME_TEMPLATE.format(task_id=context.task_id),
            context.course_id,
            date
        )
        if len(error_rows) > 0:
            error_rows = [error_headers] + error_rows
            upload_csv_to_report_store(
                error_rows,
                self.ERR_REPORT_NAME_TEMPLATE.format(task_id=context.task_id),
                context.course_id,
                date
            )

    def _error_rows_not_found(self, not_found_usernames):
        message = "User is not enrolled on course or doesn't exist"
        return [[-1, username, message] for username in not_found_usernames]

    def push_results(self, context):
        callback_url = context.callback_url
        csv_url, csv_err_url = self._get_report_urls(context)
        try:
            PlpApiClient().push_grade_api_result(callback_url, csv_url, csv_err_url)
        except Exception as e:
            logging.error("Failed push to PLP:{}".format(str(e)))

    def _get_report_urls(self, context):
        report_store = ReportStore.from_config(config_name='GRADES_DOWNLOAD')
        files_urls_pairs = report_store.links_for(context.course_id)
        get_first = lambda iterable: iterable[0] if len(iterable) else None
        find_by_name = lambda name: get_first([url for filename, url in files_urls_pairs if name in filename])

        report_name = self.REPORT_NAME_TEMPLATE.format(task_id=context.task_id)
        err_report_name = self.REPORT_NAME_TEMPLATE.format(task_id=context.task_id)

        csv_url = find_by_name(report_name)
        csv_err_url = find_by_name(err_report_name)
        return csv_url, csv_err_url


def upload_user_grades_csv(_xmodule_instance_args, _entry_id, course_id, _task_input, action_name):
    return UsersCourseGradeReport.generate(_xmodule_instance_args, _entry_id, course_id, _task_input, action_name)
