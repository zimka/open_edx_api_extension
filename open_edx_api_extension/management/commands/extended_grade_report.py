"""
Management command to calculate and store extended grade report
"""

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from opaque_keys.edx.keys import CourseKey
from django.test.client import RequestFactory
from open_edx_api_extension.tasks import kns_submit_calculate_grades_csv


class Command(BaseCommand):
    help = "Calculate and stores extended grade reports"

    def add_arguments(self, parser):
        parser.add_argument('course_id')

    def handle(self, *args, **options):
        """Execute the command"""
        course_id = options.get('course_id', None)
        try:
            course_key = CourseKey.from_string(course_id)
        except Exception as e:
            raise CommandError("Broken key: {}".format(str(e)))
        factory = RequestFactory()
        request = factory.get('/')
        request.user = User.objects.filter(is_superuser=True).first()
        kns_submit_calculate_grades_csv(request, course_key)
