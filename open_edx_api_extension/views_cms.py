import json
import logging

from contentstore.utils import reverse_course_url
from contentstore.views.course import _create_or_rerun_course
from course_modes.models import CourseMode
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.views.decorators.csrf import csrf_exempt
from opaque_keys import InvalidKeyError
from opaque_keys.edx.keys import CourseKey
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from util.json_request import JsonResponse, expect_json
from xmodule.course_module import DEFAULT_START_DATE
from xmodule.modulestore.django import modulestore

from openedx.core.djangoapps.course_groups.cohorts import set_course_cohorted
from openedx.core.djangoapps.models.course_details import CourseDetails
from openedx.core.lib.api.permissions import ApiKeyHeaderPermission

log = logging.getLogger(__name__)

User = get_user_model()

@csrf_exempt
@expect_json
@api_view(['POST'])
@permission_classes([ApiKeyHeaderPermission])
def create_or_update_course(request):
    """
        **Use Case**

            Create or edit course.

        **Example Requests**

            POST /api/extended/course/{
                "org": "test_org",
                "number": "test_course_num",
                "display_name": "TEST COURSE NAME",
                "run": "test_course_run",
                "start_date": "2016-09-01",
                "enrollment_start": "2016-08-15",
                "intro_video": "jsUdxcBsym0?list=PLWdgcBEz6133fTE9ePks31tT1QBLNaxFe",
                "syllabus": "123",
                "short_description": "456",
                "overview": "789",
                "effort": "40",
                "language": "ru",
                "course_modes": [
                    {
                        "mode": "honor",
                        "title": "test"
                    }
                ]
            }

        **Post Parameters**

            * org: Organization that owns course (slug)

            * number: Course slug

            * display_name: Course run display name for edX

            * run: Course run slug

            * start_date: Date when course starts

            * enrollment_start: Date when enrollment for course is opened

            * intro_video: Code of course introduction video on youtube (with player parameters)

            * syllabus: Course syllabus

            * short_description: Course short description

            * overview: Course overview

            * effort: Course effort (ni weeks)

            * language: Two-letter code of course language

            * course_modes: List of course modes.

                Course mode params:

                    * mode: Mode type ("audit", "honor" or "verified")

                    * price: Course mode price

                    * currency: Currency of course mode price

                    * title: Course mode title

                    * description: Course mode description

                    * upgrade_deadline: Last date when user can be enrolled/reenrolled to this mode

        **Response Values**

            * url: Course URL for CMS and LMS
            * course_key: The unique identifier for the course (full slug)
    """

    global_stuff = User.objects.filter(is_staff=True).first()
    if global_stuff is not None:
        request.user = global_stuff
    else:
        raise PermissionDenied()
    course_key = modulestore().make_course_key(request.json["org"], request.json["number"], request.json["run"])
    with modulestore().bulk_operations(course_key):
        course_key = modulestore().has_course(course_key)
        if course_key is None:
            response = _create_or_rerun_course(request)
            if response.status_code >= 400:
                return response
            course_key_string = json.loads(response.content).get("course_key")
            if course_key_string is not None:
                course_key = CourseKey.from_string(course_key_string)
            else:
                return response
        course_data = request.json.copy()
        if course_data["start_date"] is None:
            course_data["start_date"] = format(DEFAULT_START_DATE, "%Y-%m-%d")
        course_data["end_date"] = format(DEFAULT_START_DATE, "%Y-%m-%d")
        course_data["enrollment_end"] = format(DEFAULT_START_DATE, "%Y-%m-%d")
        CourseDetails.update_from_json(course_key, course_data, global_stuff)
        set_course_cohorted(course_key, True)
        modes = request.json.get("course_modes", [])
        CourseMode.objects.filter(course_id=course_key).exclude(mode_slug__in=[mode["mode"] for mode in modes]).delete()
        for mode in modes:
            mode_params = {
                "course_id": course_key,
                "mode_slug": mode["mode"]
            }
            if "price" in mode:
                mode_params["min_price"] = mode["price"]
            if "currency" in mode:
                mode_params["currency"] = mode["currency"]
            if "title" in mode:
                mode_params["mode_display_name"] = mode["title"]
            if "description" in mode:
                mode_params["description"] = mode["description"]
            if "upgrade_deadline" in mode:
                mode_params["_expiration_datetime"] = mode["upgrade_deadline"]
            CourseMode.objects.update_or_create(course_id=course_key, mode_slug=mode["mode"], defaults=mode_params)
        return JsonResponse({
            'url': reverse_course_url('course_handler', course_key),
            'course_key': unicode(course_key)
        })


@csrf_exempt
@expect_json
@api_view(['POST'])
@permission_classes([ApiKeyHeaderPermission])
def rerun_course(request):
    """
        **Use Case**

            Rerun course.

        **Example Requests**

            POST /api/extended/course-rerun/{
                "org": "test_org",
                "number": "test_course_num",
                "display_name": "TEST COURSE NAME",
                "run": "test_course_run",
                "source_course_key": "course-v1:source_org+source_course+source_run",
                "start": "2016-09-01"
            }

        **Post Parameters**

            * org: Organization that owns course (slug)

            * number: Course slug

            * display_name: Course run display name for edX

            * run: Course run slug

            * source_course_key: full slug of source course for rerun.

            * start: Date when course starts

        **Response Values**

            If all ok:
                response with 200 code
                    * url: Course URL for CMS and LMS
                    * course_key: The unique identifier for the course (full slug)
            else:
                response with 400 code
                    * error: Error description
    """

    global_stuff = User.objects.filter(is_staff=True).first()
    if global_stuff is not None:
        request.user = global_stuff
    else:
        raise PermissionDenied()

    missing_parameters = {"org", "number", "run", "display_name", "source_course_key"} - request.json.viewkeys()
    if missing_parameters:
        return JsonResponse({"error": "Some parameters missing: {}".format(", ".join(missing_parameters))},
                            status=status.HTTP_400_BAD_REQUEST)

    course_key = modulestore().make_course_key(request.json["org"], request.json["number"], request.json["run"])
    course_key = modulestore().has_course(course_key)
    if course_key is not None:
        return JsonResponse({"error": "Course with such parameters already exists"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        source_course_key = CourseKey.from_string(request.json["source_course_key"])
    except InvalidKeyError:
        return JsonResponse({"error": "Wrong source_course_key format"}, status=status.HTTP_400_BAD_REQUEST)
    source_course_key = modulestore().has_course(source_course_key)
    if source_course_key is None:
        return JsonResponse({"error": "Source course doesn't exist"}, status=status.HTTP_400_BAD_REQUEST)

    return _create_or_rerun_course(request)


@csrf_exempt
@api_view(['GET'])
@permission_classes([ApiKeyHeaderPermission])
def check_course_exists(request):
    course_id = request.query_params.get('course_id', None)
    try:
        course_key = CourseKey.from_string(course_id)
    except InvalidKeyError:
        return JsonResponse({"error": "Wrong course_id format"}, status=status.HTTP_400_BAD_REQUEST)
    course_key = modulestore().has_course(course_key)
    return JsonResponse({"exists": course_key is not None})
