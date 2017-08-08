# -*- coding: utf-8 -*-
from django.conf import settings
from django.http.response import JsonResponse
import logging
import requests


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
            mes = u" (forbidden by PLP: {})".format(reason)
            results[0]["identifier"] += mes #hack
            logging.info("User {} uneroll rejected; reason: {}".format(username, reason))
        except KeyError as e:
            logging.error("PLP api error: {}".format(str(e)))
        return 0, JsonResponse(response_payload)
