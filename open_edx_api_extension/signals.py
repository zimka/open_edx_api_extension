from django.dispatch import receiver

try:
    from openedx.core.djangoapps.course_groups.cohorts import COURSE_COHORT_ADD
except (ImportError, AttributeError) as e:
    COURSE_COHORT_ADD = None
    def receiver(*args, **kwargs):
        return lambda x: x
    logging.error("Failed to enable course shifts push into PLP: import error:{}".format(e))

from .api_client import PlpApiClient


@receiver(COURSE_COHORT_ADD)
def push_course_user_group_changed(sender, **kwargs):
    """
    Pushes CourseShiftGroup to PLP: creation, deletion and start_date change.
    """
    course_id = kwargs['course_id']
    username = kwargs['username']
    group_name = kwargs['group_name']
    if group_name.lower()[0:8] == 'verified' and len(group_name.lower()) > 8:
        group_name = group_name[8:].strip()
    PlpApiClient().push_course_user_group_changed(course_id, username, group_name)
