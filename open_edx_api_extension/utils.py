# -*- coding: utf-8 -*-
import logging
import os
import requests

from django.conf import settings
from django.http.response import JsonResponse
from django.utils.translation import ugettext as _
from lms.djangoapps.grades.new.course_grade_factory import CourseGradeFactory


def plp_check_unenroll(identifiers, username, session_name, banned_by):
    """
    Запрос через PLP разрешения на отчисление И бан студента
    :return: status, response
    status: 1 - OK, 0 - Forbidden
    response: None or Response(400)
    """
    try:
        plp_url = settings.PLP_URL
        plp_ban = settings.PLP_BAN_ON
        if not plp_ban:
            return 1, None
    except AttributeError:
        return 1, None

    if len(identifiers) != 1:
        results = [{
            'identifier': "You can ban only one user at a time. Nobody banned.",
            'error': True,
        }]
        response_payload = {
            'action': "unenroll",
            'results': results,
            'auto_enroll': False,
        }
        return 0, JsonResponse(response_payload)
    data = {
        "username": username,
        "session": session_name,
        "banned_by": banned_by
    }
    request_url = "{}/api/ban_user/".format(plp_url)
    headers = {'x-plp-api-key': settings.PLP_API_KEY}
    plp_response = requests.post(request_url, data=data, headers=headers)
    results = [{
        'identifier': username,
        'error': True,
        }]
    response_payload = {
        'action': "unenroll",
        'results': results,
        'auto_enroll': False,
    }

    if plp_response.status_code == 200:
        return 1, None
    else:
        data = plp_response.json()
        try:
            reason = data.get('reason', "No reason")
            mes = _(u" (forbidden by PLP: {})").format(_(reason))
            results[0]["identifier"] += mes #hack
            logging.info("User {} uneroll rejected; reason: {}".format(username, reason))
        except KeyError as e:
            logging.error("PLP api error: {}".format(str(e)))
        return 0, JsonResponse(response_payload)


def student_grades(student, course):
    """Returns student's grade_summary for course"""
    cg = CourseGradeFactory().create(student, course)
    return cg.summary

 
def get_custom_grade_config():
    # Perform the actual upload
    custom_grades_download = hasattr(settings, "CUSTOM_GRADES_DOWNLOAD")
    return "CUSTOM_GRADES_DOWNLOAD" if custom_grades_download else "GRADES_DOWNLOAD"


def store_links_for_user(store, course_id):
        """
        For a given `course_id`, return a list of `(filename, url)` tuples.
        Calls the `url` method of the underlying storage backend. Returned
        urls can be plugged straight into an href
        """
        course_dir = store.path_to(course_id)
        try:
            _, filenames = store.storage.listdir(course_dir)
        except OSError:
            # Django's FileSystemStorage fails with an OSError if the course
            # dir does not exist; other storage types return an empty list.
            return []
        files = [(filename, os.path.join(course_dir, filename)) for filename in filenames]
        files.sort(key=lambda f: store.storage.modified_time(f[1]), reverse=True)
        return [
            (filename, store.storage.url(full_path))
            for filename, full_path in files
        ]
