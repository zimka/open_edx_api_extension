import logging
import requests

from django.conf import settings
log = logging.getLogger(__name__)


def _get_json(response):
    try:
        return response.json()
    except:
        return {}


class PlpApiClient(object):
    """
    API client for communication with PLP.
    Checks that settings are setup, otherwise logs errors
    Returns data for supported actions
    """
    PLP_API_URLS = {
        "shift_group":"/api/course-shift-changed/",
        "shift_membership":"/api/user-course-shift-changed/",
        "shift_settings":"/api/course-shift-settings-changed/",
        "betatest_leeway":"/api/course-betatest-leeway/"
    }

    def __init__(self):
        self.base_url = getattr(settings, "PLP_URL", None)
        self.api_key = getattr(settings, "PLP_API_KEY", None)
        if self.base_url is None or self.api_key is None:
            self._request = self._dummy

    def normalize_url(self, url, lms_url):
        if url.startswith("http://") or url.startswith("https://"):
            return url
        return lms_url.strip("/") + url

    def push_grade_api_result(self, path, local_csv_url, local_csv_err_url):
        """
        Returns url with requests CSV grade sheet
        """
        lms_url = getattr(settings, "LMS_ROOT_URL", None)
        if not lms_url:
            log.error("Undefined LMS_ROOT_URL. Can't return to PLP CSV file absolute url")
            return

        data = {"url": self.normalize_url(local_csv_url, lms_url)}
        if local_csv_err_url:
            data["url_err"] = self.normalize_url(local_csv_err_url, lms_url)
        return self._post(path, data)


    def push_shift_group(self, course_key, name, start_date):
        url = self.PLP_API_URLS["shift_group"]
        data = {
            "course_id": str(course_key),
            "name": name
        }

        if start_date:
            data["start_date"] = start_date
            return self._post(url, data)
        else:
            return self._delete(url, data)

    def push_shifts_settings(self, course_key, enroll_before_days, enroll_after_days):
        url = self.PLP_API_URLS["shift_settings"]
        data = {
            "course_id": str(course_key),
            "enroll_before_days": enroll_before_days,
            "enroll_after_days": enroll_after_days
        }
        return self._post(url, data)

    def push_shift_membership(self, user, shift_from, shift_to, requester):
        url = self.PLP_API_URLS["shift_membership"]
        username = user.username
        course_id = shift_from.course_key if shift_from else shift_to.course_key
        data = {
            "username": username,
            "course_id": str(course_id),
        }

        if shift_from and shift_to:
            data["action"] = "transfer"
            data["name"] = shift_to.name
        elif shift_to:
            data["action"] = "create"
            data["name"] = shift_to.name
        else:
            data["action"] = "delete"
            data["name"] = shift_from.name
        requester_name =  username
        if requester and not requester.is_anonymous():
            requester_name = requester.username
        data["requester"] = requester_name
        self._post(url, data)

    def push_betatest_leeway(self, course_key, value):
        url = self.PLP_API_URLS["betatest_leeway"]
        if value is None:
            value = 0
        data = {
            "course_id": str(course_key),
            "days": int(value)
        }
        self._post(url, data)

    def _post(self, path, data, is_json=False):
        return self._request(path, data, is_json, delete=False)

    def _delete(self, path, data, is_json=False):
        return self._request(path, data, is_json, delete=True)

    def push_course_user_group_changed(self, course_id, username, group_name):
        data = {}
        data['course_id'] = str(course_id)
        data['username'] = username
        data['group_name'] = group_name
        self._request('api/user-add-group', data, False)


    def _request(self, path, data, is_json, delete=False):
        headers = {'x-plp-api-key': self.api_key}
        if is_json:
            headers['Content-Type'] = 'application/json'
        request_url = "{}/{}/".format(
            self.base_url.strip("/"),
            path.strip("/")
        )
        if not delete:
            plp_response = requests.post(request_url, data=data, headers=headers)
        else:
            plp_response = requests.delete(request_url, data=data, headers=headers)

        if plp_response.ok:
            return _get_json(plp_response)
        else:
            message = "PlpApiClient error: request ({}, {});".format(request_url, str(data))
            message += "response ({}, {})".format(plp_response.status_code, _get_json(plp_response))
            log.error(message)
            return {}

    def _dummy(self, *args, **kwargs):
        """
        If settings are not setup we log every attempt to call PLP
        but do nothing
        """
        message = "Tried to use PlpApiClient, but settings are incorrect. " \
                  "You have to configure PLP_URL and PLP_API_KEY to use PlpApiClient."
        log.error(message)
        return {}
