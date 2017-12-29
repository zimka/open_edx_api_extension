import json
import logging
import requests

from django.conf import settings

try:
    from course_shifts import shift_membership_changed_signal
    from django.dispatch import receiver
except ImportError as e:
    shift_membership_changed_signal = None

    def receiver(*args, **kwargs):
        return lambda x: x
    logging.error("Failed to enable course shifts push into PLP: import error")

log = logging.getLogger(__name__)


def check_plp_course_shift_settings(func):
    """
    If some necessary settings are not setup we will log every
    attempt to push info into PLP as error.
    """
    plp_base_url = getattr(settings, "PLP_URL", None)
    if not plp_base_url:
        return lambda *ars, **kwargs: log.error("Course shifts can't be pushed: PLP_URL is not defined")

    plp_api_key = getattr(settings, "PLP_API_KEY", None)
    if not plp_api_key:
        return lambda *args, **kwargs: log.error("Course shifts can't be pushed: PLP_API_KEY is not defined")

    return func


@receiver(shift_membership_changed_signal)
@check_plp_course_shift_settings
def push_course_shifts_info(sender, shift_group, specific_username=None, is_deleting=False, **kwargs):
    """
    When course shifts changed, push changes into PLP:
    1. Single user transferred from one shift to another
    (or removed from shifts at all, but this is impossible using provided UI)
    2. Course Shift start_date was changed
    3. Course Shift was deleted (not encouraged, but still possible)
    """
    plp_shift_handler_url = getattr(
        settings,
        "PLP_COURSE_SHIFTS_HANDLER_URL",
        "/api/user-course-shift-changed/"
    )
    url = settings.PLP_URL + plp_shift_handler_url
    if is_deleting:
        date = shift_group.settings.course_start_date
    else:
        date = shift_group.start_date

    if specific_username:
        users_list = [specific_username]
    else:
        users_list = [u.username for u in shift_group.users.all()]
        if not users_list:
            # empty course shift, don't push
            return

    data = {
        "course_id": str(shift_group.course_key),
        "usernames": users_list,
        "start_date": str(date)
    }
    headers = {'x-plp-api-key': settings.PLP_API_KEY, 'Content-Type': 'application/json'}

    error_message_template = "Failed course shifts push to plp. Reason: {}"
    try:
        response = requests.post(url, data=json.dumps(data), headers=headers)
    except Exception as e:
        log.error(error_message_template.format(str(e)))
        return

    if response.ok:
        return

    response_message = "{} {};".format(response.status_code, response.reason)
    try:
        response_message += str(response.json())
    except ValueError:
        pass
    log.error(error_message_template.format(response_message))
