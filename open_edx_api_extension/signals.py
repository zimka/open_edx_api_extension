import logging

from django.dispatch import receiver
from .api_client import PlpApiClient

try:
    from course_shifts.models import CourseShiftGroup, CourseShiftSettings, CourseShiftGroupMembership
    group_signal = CourseShiftGroup.changed_signal
    settings_signal = CourseShiftSettings.changed_signal
    membership_signal = CourseShiftGroupMembership.method_called_signal
except (ImportError, AttributeError) as e:
    group_name_signal = group_signal = settings_signal = membership_signal = None


from django.dispatch import receiver

try:
    from openedx.core.djangoapps.course_groups.cohorts import COURSE_COHORT_ADD
except (ImportError, AttributeError) as e:
    COURSE_COHORT_ADD = None
    def receiver(*args, **kwargs):
        return lambda x: x
    logging.error("Failed to enable course shifts push into PLP: import error:{}".format(e))


log = logging.getLogger(__name__)


@receiver(group_signal)
def push_course_shift_group_changed(sender, old_fields, new_fields, forced_fields, **kwargs):
    """
    Pushes CourseShiftGroup to PLP: creation, deletion and start_date change.
    """
    course_key = forced_fields['course_key']
    name = forced_fields['name']
    start_date = new_fields.get('start_date', None)
    PlpApiClient().push_shift_group(course_key, name, start_date)


@receiver(settings_signal)
def push_course_shifts_settings_changed(sender, old_fields, new_fields, forced_fields, **kwargs):
    """
    Pushes CourseShiftSettings creation and deletion to PLP. Doesn't push deletion, because
    it's impossible using insutructor or admin interfaces
    """
    if new_fields:
        # otherwise we have deleted settings, it's exceptional case
        # that doesn't need push to plp
        PlpApiClient().push_shifts_settings(**forced_fields)


@receiver(membership_signal)
def push_course_shift_membership_changed(sender, method_name, args, kwargs, result, **true_kwargs):
    """
    Pushes CourseShiftGroupMembership change. It's supposed that membership changed via .transfer_user method.
    """
    if method_name == "transfer_user":
        if not result:
            return
        user = args[0]
        shift_from = args[1]
        shift_to = args[2]
        requester = None
        if 'requester' in kwargs:
            requester = kwargs['requester']
        if not shift_to and not shift_from:
            # just to check, impossible case
            return
        PlpApiClient().push_shift_membership(user, shift_from, shift_to, requester)
    else:
        log.error("Unexpected signal source: {}".format(method_name))


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
