import logging
from datetime import timedelta
from django.utils import timezone

from django.core.urlresolvers import reverse
from django.conf import settings
from edx_proctoring.api import get_all_exams_for_course
from enrollment.serializers import CourseEnrollmentSerializer
from lms.djangoapps.courseware.access import has_access
from openedx.core.djangoapps.course_groups.models import CourseUserGroup
from opaque_keys.edx.keys import CourseKey, UsageKey
from student.models import CourseEnrollment
from xmodule.modulestore.django import modulestore

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
                                                  user__username=username)
    system = request.data.get('system')
    result = {}
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
            name=VERIFIED
        )

        if course_id not in result and cohorts.exists():
            proctoring_service = modulestore().get_course(CourseKey.from_string(course_id)).proctoring_service
            if system and system != proctoring_service:
                continue
            result[course_id] = {
                "id": course_id,
                "name": course.display_name,
                "uri": request.build_absolute_uri(
                    reverse('course_structure_api:v0:detail',
                            kwargs={'course_id': course_id})),
                "image_url": course.course_image_url,
                "start": course.start,
                "end": course.end,
                "system": proctoring_service,
                'exams': []
            }
            exams = get_all_exams_for_course(course_id=course.id)
            for exam in exams:
                if exam['is_proctored']:
                    item_id = UsageKey.from_string(exam['content_id'])
                    item = modulestore().get_item(item_id)
                    exam['visible_to_staff_only'] = item.visible_to_staff_only
                    exam_review_checkbox = item.exam_review_checkbox
                    if 'voice' in exam_review_checkbox:
                        exam_review_checkbox['voices'] = exam_review_checkbox.pop('voice')
                    if 'aid' in exam_review_checkbox:
                        exam_review_checkbox['human_assistant'] = exam_review_checkbox.pop('aid')
                    exam['exam_review_checkbox'] = exam_review_checkbox
                    oldest = None
                    due_dates = []
                    for vertical in item.get_children():
                        if vertical.due:
                            due_dates.append(vertical.due)
                    if due_dates:
                        oldest = min(due_dates)
                    exam['deadline'] = oldest
                    exam['start'] = item.start
                    result[course_id]['exams'].append(exam)
            result = {key: value for key, value in result.items() if
                      len(value['exams']) > 0}
    return result


def get_course_calendar(user, course_key_string):
    try:
        from icalendar import Calendar, Event
    except ImportError:
        logging.error("Calendar module not installed")
        return

    course_key = CourseKey.from_string(course_key_string)
    checked = ["course", "vertical", "sequential"]
    items = modulestore().get_items(course_key)
    hour = timedelta(hours=1)

    cal = Calendar()
    for num, item in enumerate(items):
        if not item.category in checked:
            continue
        if not item.graded:
            continue
        if not has_access(user, "load", item, course_key=item.location):
            continue
        if not item.due:
            continue
        if item.category != 'course':
            format = item.format or item.get_parent().format
        else:
            format = 'course'
        url = u'http://{}{}'.format(settings.SITE_NAME, _reverse_usage(item))
        event = Event()
        summary = u"Type: {}; Name: {}({})".format(format, item.display_name, url).encode('utf-8')
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

