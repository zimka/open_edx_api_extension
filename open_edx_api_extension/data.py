import logging
from datetime import timedelta
from django.utils import timezone

from django.core.urlresolvers import reverse
from django.conf import settings
from edx_proctoring.api import get_all_exams_for_course
from enrollment.serializers import CourseEnrollmentSerializer
from lms.djangoapps.courseware.access import has_access
from openedx.core.djangoapps.course_groups.models import CourseUserGroup
from opaque_keys.edx.keys import CourseKey
from student.models import CourseEnrollment
from xmodule.modulestore.django import modulestore
from edx_proctoring.models import ProctoredCourse
from edx_proctoring.api import get_xblock_exam_params


VERIFIED = 'verified'


def get_course_enrollments(user_id=None, **kwargs):
    """
    Retrieve a list representing all aggregated data for a user's course enrollments.
    Construct a representation of all course enrollment data for a specific user.
    Args:
        user_id (str): The name of the user to retrieve course enrollment information for.
    Returns:
        A serializable list of dictionaries of all aggregated enrollment data for a user.
    """
    qset = CourseEnrollment.objects.filter(is_active=True, **kwargs)
    if user_id is not None:
        qset = qset.filter(user__username=user_id)
    qset = qset.order_by('created')
    return CourseEnrollmentSerializer(qset).data  # pylint: disable=no-member


def get_user_proctored_exams(username, request):
    enrollments = CourseEnrollment.objects.filter(is_active=True,
                                                  user__username=username,
                                                  mode=VERIFIED)
    system = request.data.get('system')
    if not system:
        system = request.GET.get('system')
    if system:
        system = system.strip()
        if 'ITMO' in system:
            system = 'ITMO'

    result = {}

    course_ids = []

    for enrollment in enrollments:
        course = enrollment.course
        if course and course.end and course.end < timezone.now():
            continue
        try:
            course_id = str(course.id)
        except AttributeError:
            continue

        cohorts = CourseUserGroup.objects.filter(
            course_id=enrollment.course_id,
            users__username=username,
            group_type=CourseUserGroup.COHORT,
            name__startswith=VERIFIED
        )

        if course_id not in course_ids and cohorts.exists():
            course_ids.append(course_id)

    courses = []
    if course_ids:
        courses = ProctoredCourse.fetch_by_course_ids(course_ids)

    for course in courses:
        course_id = course.edx_id
        proctoring_service = [c.strip() for c in course.available_proctoring_services.split(',')]
        if system and system not in proctoring_service:
            continue
        result[course_id] = {
            'id': course_id,
            'name': course.display_name,
            'uri': request.build_absolute_uri(
                reverse('course_structure_api:v0:detail',
                        kwargs={'course_id': course_id})),
            'image_url': course.image_url,
            'start': course.start,
            'end': course.end,
            'system': system,
            'exams': []
        }
        exams = get_all_exams_for_course(course_id=course.id, detailed=True)
        for exam in exams:
            if exam['is_proctored']:
                exam_data = exam['extended_params'] if exam['extended_params'] and exam['extended_params']['updated'] \
                    else get_xblock_exam_params(exam['content_id'])

                exam_proctoring_system = exam_data['service']
                if len(proctoring_service) > 1 and not exam_proctoring_system:
                    logging.warning('For course {} and exam {} proctoring service not specified. Available are {}'
                                    .format(course_id, exam, proctoring_service))
                    continue
                if len(proctoring_service) > 1 and exam_proctoring_system and exam_proctoring_system != system:
                    logging.warning('For course {} and exam {} proctoring service is {}, but system is {}'
                                    .format(course_id, exam, exam_proctoring_system, system))
                    continue

                exam_review_checkbox = exam_data['exam_review_checkbox']
                if 'voice' in exam_review_checkbox:
                    exam_review_checkbox['voices'] = exam_review_checkbox.pop('voice')
                if 'aid' in exam_review_checkbox:
                    exam_review_checkbox['human_assistant'] = exam_review_checkbox.pop('aid')

                exam['exam_review_checkbox'] = exam_review_checkbox
                exam['visible_to_staff_only'] = exam_data['visible_to_staff_only']
                exam['start'] = exam_data['start']
                exam['deadline'] = exam_data['deadline']

                result[course_id]['exams'].append(exam)
        result = {key: value for key, value in result.items() if
                  len(value['exams']) > 0}
    return result


def get_course_calendar(user, course_key_string):
    try:
        from icalendar import Calendar, Event
    except ImportError:
        logging.error('Calendar module not installed')
        return

    course_key = CourseKey.from_string(course_key_string)
    checked = ['course', 'vertical', 'sequential']
    items = modulestore().get_items(course_key)
    hour = timedelta(hours=1)

    cal = Calendar()
    for num, item in enumerate(items):
        if not item.category in checked:
            continue
        if not item.graded:
            continue
        if not has_access(user, 'load', item, course_key=item.location.course_key):
            continue
        if not item.due:
            continue
        if item.category != 'course':
            format = item.format or item.get_parent().format
        else:
            format = 'course'
        url = u'http://{}{}'.format(settings.SITE_NAME, _reverse_usage(item))
        event = Event()
        summary = u'Type: {}; Name: {}({})'.format(format, item.display_name, url).encode('utf-8')
        event.add('summary', summary)
        event.add('dtstart', item.due - hour)
        event.add('dtend', item.due)
        cal.add_component(event)
    text = cal.to_ical().decode('utf-8')
    return text


def _reverse_usage(item):
    from lms.djangoapps.courseware.url_helpers import get_redirect_url
    course_key = item.location.course_key
    url = get_redirect_url(course_key, item.location)
    try:
        url = url.split('?')[0]
    except AttributeError:
        pass
    return url

