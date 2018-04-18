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

        return self._request(path, data)


    def push_course_user_group_changed(self, course_id, username, group_name):
        data = {}
        data['course_id'] = str(course_id)
        data['username'] = username
        data['group_name'] = group_name
        self._request('api/user-add-group', data)

    def _request(self, path, data):
        headers = {'x-plp-api-key': self.api_key}#, 'Content-Type': 'application/json'}
        request_url = "{}/{}/".format(
            self.base_url.strip("/"),
            path.strip("/")
        )
        plp_response = requests.post(request_url, data=data, headers=headers)
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
