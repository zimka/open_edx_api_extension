import logging

from django.core.exceptions import ObjectDoesNotExist
from django.conf import settings
from django.http import HttpResponse
from django.db import transaction
from django.utils.decorators import method_decorator

from rest_framework.generics import RetrieveAPIView, ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from bulk_email.models import Optout

from cors_csrf.decorators import ensure_csrf_cookie_cross_domain
from course_modes.models import CourseMode
from course_structure_api.v0 import serializers
from course_structure_api.v0.views import CourseViewMixin
from courseware import courses

from django_comment_common.models import Role, FORUM_ROLE_STUDENT
from embargo import api as embargo_api
from instructor.offline_gradecalc import student_grades

from opaque_keys.edx.keys import CourseKey
from opaque_keys import InvalidKeyError
from student.models import User, CourseEnrollment, CourseAccessRole
from xmodule.modulestore.django import modulestore

from openedx.core.djangoapps.course_groups.cohorts import (
    is_course_cohorted, is_cohort_exists, add_cohort, add_user_to_cohort, remove_user_from_cohort, get_cohort_by_name,
)
from openedx.core.djangoapps.course_groups.models import CourseUserGroup
from openedx.core.djangoapps.user_api.preferences.api import update_email_opt_in
from openedx.core.lib.api.authentication import (
    SessionAuthenticationAllowInactiveUser,
    OAuth2AuthenticationAllowInactiveUser,
)
from openedx.core.lib.api.permissions import ApiKeyHeaderPermissionIsAuthenticated, ApiKeyHeaderPermission

from enrollment import api
from enrollment.errors import (
    CourseEnrollmentError,
    CourseModeNotFoundError, CourseEnrollmentExistsError
)
from enrollment.views import ApiKeyPermissionMixIn, EnrollmentCrossDomainSessionAuth, EnrollmentListView

from eventtracking import tracker
from track import views as track_views

from open_edx_api_extension.serializers import CourseWithExamsSerializer
from .data import get_course_enrollments, get_user_proctored_exams, get_course_calendar

log = logging.getLogger(__name__)
VERIFIED = 'verified'

try:
    from edx_proctoring.models import ProctoredExamStudentAttempt
    from edx_proctoring.api import remove_exam_attempt
except ImportError:
    ProctoredExamStudentAttempt = None

class LibrariesList(ListAPIView):
    """
    **Use Case**
        Get a paginated list of libraries in the whole edX Platform.
        The list can be filtered by course_id.
        Each page in the list can contain up to 10 courses.
    **Example Requests**
          GET /api/extended/libraries/
    **Response Values**
        * count: The number of courses in the edX platform.
        * next: The URI to the next page of courses.
        * previous: The URI to the previous page of courses.
        * num_pages: The number of pages listing courses.
        * results:  A list of courses returned. Each collection in the list
          contains these fields.
            * id: The unique identifier for the course.
              "course".
            * org: The organization specified for the course.
            * course: The course number.
    """
    # Using EDX_API_KEY for access to this api
    authentication_classes = (SessionAuthenticationAllowInactiveUser,
                              OAuth2AuthenticationAllowInactiveUser)
    permission_classes = ApiKeyHeaderPermissionIsAuthenticated,

    def list(self, request, *args, **kwargs):
        lib_info = [
            {
                "display_name": lib.display_name,
                "library_key": unicode(lib.location.library_key),
                "org": unicode(lib.location.library_key.org),
            }
            for lib in modulestore().get_libraries()
            ]
        return Response(lib_info)


class CourseUserResult(CourseViewMixin, RetrieveAPIView):
    """
    **Use Case**

        Get result user for a specific course.

    **Example Request**:

        GET /api/extended/courses/{course_id}/{username}/

    **Response Values**

        * id: The unique identifier for the user.

        * username: The username of the user.

        * email: The email of the user.

        * realname: The realname of the user.

        * grade_summary: Contains student grade details:

            * section_breakdown: This is a list of dictionaries which provide details on sections that were graded:
                * category: A string identifying the category.
                * percent: A float percentage for the section.
                * detail: A string explanation of the score. E.g. "Homework 1 - Ohms Law - 83% (5/6)".
                * label: A short string identifying the section. E.g. "HW  3".

            * grade:  A final letter grade.

            * totaled_scores: totaled scores, which is passed to the grader.

            * percent: Contains a float value, which is the final percentage score for the student.

            * grade_breakdown: This is a list of dictionaries which provide details on the contributions
                               of the final percentage grade. This is a higher level breakdown, for when the grade is
                               constructed of a few very large sections (such as Homeworks, Labs, a Midterm, and a Final):
                * category: A string identifying the category.
                * percent: A float percentage in the breakdown. All percents should add up to the final percentage.
                * detail: A string explanation of this breakdown. E.g. "Homework - 10% of a possible 15%".
    """

    @CourseViewMixin.course_check
    def get(self, request, **kwargs):
        username = self.kwargs.get('username')
        enrolled_students = CourseEnrollment.objects.users_enrolled_in(
            self.course_key).filter(username=username)
        course = courses.get_course(self.course_key)

        if not enrolled_students:
            return Response({
                "error_description": "User is not enrolled for the course",
                "error": "invalid_request"
            })

        student_info = [
            {
                'username': student.username,
                'id': student.id,
                'email': student.email,
                'grade_summary': student_grades(student, request, course),
                'realname': student.profile.name,
            }
            for student in enrolled_students
            ]
        return Response(student_info)


class CourseListMixin(object):
    lookup_field = 'course_id'
    paginate_by = 10000
    paginate_by_param = 'page_size'
    serializer_class = serializers.CourseSerializer
    # Using EDX_API_KEY for access to this api
    authentication_classes = (SessionAuthenticationAllowInactiveUser,
                              OAuth2AuthenticationAllowInactiveUser)
    permission_classes = ApiKeyHeaderPermissionIsAuthenticated,

    def get_queryset(self):
        course_ids = self.request.query_params.get('course_id', None)

        results = []
        if course_ids:
            course_ids = course_ids.split(',')
            for course_id in course_ids:
                course_key = CourseKey.from_string(course_id)
                course_descriptor = courses.get_course(course_key)
                results.append(course_descriptor)
        else:
            results = modulestore().get_courses()

        # Ensure only course descriptors are returned.
        results = (course for course in results if
                   course.scope_ids.block_type == 'course')

        # Sort the results in a predictable manner.
        return sorted(results, key=lambda course: unicode(course.id))


class CourseList(CourseListMixin, ListAPIView):
    """
    Inspired from:
    lms.djangoapps.course_structure_api.v0.views.CourseList

    **Use Case**
        Get a paginated list of courses in the whole edX Platform.
        The list can be filtered by course_id.
        Each page in the list can contain up to 10 courses.
    **Example Requests**
          GET /api/extended/courses/
    **Response Values**
        * count: The number of courses in the edX platform.
        * next: The URI to the next page of courses.
        * previous: The URI to the previous page of courses.
        * num_pages: The number of pages listing courses.
        * results:  A list of courses returned. Each collection in the list
          contains these fields.
            * id: The unique identifier for the course.
            * name: The name of the course.
            * category: The type of content. In this case, the value is always
              "course".
            * org: The organization specified for the course.
            * run: The run of the course.
            * course: The course number.
            * uri: The URI to use to get details of the course.
            * image_url: The URI for the course's main image.
            * start: The course start date.
            * end: The course end date. If course end date is not specified, the
              value is null.
    """
    serializer_class = serializers.CourseSerializer


class CourseListWithExams(CourseListMixin, ListAPIView):
    """
    Gets a list of courses with proctored exams
    """
    serializer_class = CourseWithExamsSerializer


class SSOEnrollmentListView(EnrollmentListView):
    """
    Inspired from:
    common.djangoapps.enrollment.views.EnrollmentListView
    See base docs in parent class or on the web
    http://edx-platform-api.readthedocs.org/en/latest/enrollment/enrollment.html#enrollment.views.EnrollmentView
    """

    @method_decorator(ensure_csrf_cookie_cross_domain)
    def get(self, request):
        """
        There is copy-paste from parent class method.
        Only one difference we use get_course_enrollments() instead api.get_enrollments

        Gets a list of all course enrollments for the currently logged in user.
        """
        username = request.GET.get('user',
                                   request.user.is_staff and None or request.user.username)
        try:
            course_key = CourseKey.from_string(request.GET.get('course_run'))
        except InvalidKeyError:
            course_key = None

        if (
            not request.user.is_staff and request.user.username != username) and not self.has_api_key_permissions(
                request):
            # Return a 404 instead of a 403 (Unauthorized). If one user is looking up
            # other users, do not let them deduce the existence of an enrollment.
            return Response(status=status.HTTP_404_NOT_FOUND)
        try:
            if course_key:
                return Response(
                    get_course_enrollments(username, course_id=course_key))
            return Response(get_course_enrollments(username))
        except CourseEnrollmentError:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={
                    "message": (
                        u"An error occurred while retrieving enrollments for user '{username}'"
                    ).format(username=username)
                }
            )


class PaidMassEnrollment(APIView, ApiKeyPermissionMixIn):
    """
        **Use Cases**

            Called from plp by staff from admin panel for update course enrollments for group of students
            to verified course mode

            1. Enroll the list of users to verified course mode

        **Example Requests**:

            POST /api/extended/enrollment{
                "course_details":{"course_id": "edX/DemoX/Demo_Course"},
                "users": "[user1, user2, user3]"
            }

        **Post Parameters**

            * users:  The usernames of the users. Required.

            * mode: The Course Mode for the enrollment. Individual users cannot upgrade their enrollment mode from
              'honor'. Only server-to-server requests can enroll with other modes. Optional.

            * is_active: A Boolean indicating whether the enrollment is active. Only server-to-server requests are
              allowed to deactivate an enrollment. Optional.

            * course details: A collection that contains:

                * course_id: The unique identifier for the course.

            * email_opt_in: A Boolean indicating whether the user
              wishes to opt into email from the organization running this course. Optional.

            * enrollment_attributes: A list of dictionary that contains:

                * namespace: Namespace of the attribute
                * name: Name of the attribute
                * value: Value of the attribute

        **Response Values**

            200 - OK, 400 - Fail
    """
    authentication_classes = OAuth2AuthenticationAllowInactiveUser, EnrollmentCrossDomainSessionAuth
    permission_classes = ApiKeyHeaderPermissionIsAuthenticated,

    @transaction.atomic
    def post(self, request):
        """
        Enrolls the list of users in a verified course mode.
        """
        # Get the users, Course ID, and Mode from the request.

        users = request.data.get('users', [])

        if len(users) == 0:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"message": u"Users must be specified to create a new enrollment."}
            )

        course_id = request.data.get('course_details', {}).get('course_id')

        if not course_id:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"message": u"Course ID must be specified to create a new enrollment."}
            )

        try:
            course_key = CourseKey.from_string(course_id)
        except InvalidKeyError:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"message": u"No course '{course_id}' found for enrollment".format(course_id=course_id)}
            )

        # use verified course mode by default
        mode = request.data.get('mode', CourseMode.VERIFIED)

        bad_users = []
        list_users = []
        for username in users:
            try:
                user = User.objects.get(username=username)
                list_users.append(user)
            except ObjectDoesNotExist:
                bad_users.append(username)

        if len(bad_users) > 0:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={'message': u'Users: {} does not exist.'.format(', '.join(bad_users))}
            )

        for user in list_users:
            embargo_response = embargo_api.get_embargo_response(request, course_key, user)

            if embargo_response:
                return embargo_response

        current_username = None
        try:
            is_active = request.data.get('is_active')
            # Check if the requested activation status is None or a Boolean
            if is_active is not None and not isinstance(is_active, bool):
                return Response(
                    status=status.HTTP_400_BAD_REQUEST,
                    data={'message': u"'{value}' is an invalid enrollment activation status.".format(value=is_active)}
                )

            enrollment_attributes = request.data.get('enrollment_attributes')
            errors = False
            already_paid = []  # list of users with verified enrollment
            not_enrolled = []  # list of not enrolled yet or unenrolled users
            for username in users:
                current_username = username
                enrollment = api.get_enrollment(username, unicode(course_key))
                if not enrollment:
                    not_enrolled.append(username)
                elif enrollment['is_active'] is not True:
                    not_enrolled.append(username)
                elif enrollment['mode'] == CourseMode.VERIFIED:
                    already_paid.append(username)
            msg_paid = u""
            msg_not_enrolled = u""
            if len(already_paid) > 0:
                msg_paid = u'Users: {} already paid for course.'.format(', '.join(already_paid))
                errors = True
            if len(not_enrolled) > 0:
                msg_not_enrolled = u'Users: {} not enrolled for course.'.format(', '.join(not_enrolled))
                errors = True
            if errors:
                return Response(
                    status=status.HTTP_400_BAD_REQUEST,
                    data={"message": (u"'{course_id}'\n:{msg_paid}\n{msg_not_enrolled}").format(
                        course_id=course_id,
                        msg_paid=msg_paid,
                        msg_not_enrolled=msg_not_enrolled
                    ),
                    })

            # update for cohorts
            cohort_exists = is_cohort_exists(course_key, VERIFIED)
            if not cohort_exists:
                cohort = add_cohort(course_key, VERIFIED, 'manual')
            else:
                cohort = get_cohort_by_name(course_key, VERIFIED)

            for username in users:
                current_username = username
                api.update_enrollment(username, unicode(course_key), mode=mode, is_active=is_active)
                user = User.objects.get(username=username)
                course_cohorts = CourseUserGroup.objects.filter(
                    course_id=cohort.course_id,
                    users__id=user.id,
                    group_type=CourseUserGroup.COHORT
                )

                add_user_into_verified_cohort(course_cohorts, cohort, user)

            email_opt_in = request.data.get('email_opt_in', None)
            if email_opt_in is not None:
                org = course_key.org
                for username in users:
                    update_email_opt_in(username, org, email_opt_in)

            return Response(
                status=status.HTTP_200_OK,
                data={
                    "message": u"Success for course '{course_id}'.".format(course_id=course_id)
                })
        except CourseModeNotFoundError as error:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={
                    "message": (
                        u"The course mode '{mode}' is not available for course '{course_id}'."
                    ).format(mode="verified", course_id=course_id),
                    "course_details": error.data
                })
        except CourseEnrollmentExistsError as error:
            return Response(data=error.enrollment)
        except CourseEnrollmentError:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={
                    "message": (
                        u"An error occurred while creating the new course enrollment for user "
                        u"'{username}' in course '{course_id}'"
                    ).format(username=current_username, course_id=course_id)
                }
            )


class ProctoredExamsListView(APIView):
    """
    Get list of user's course and proctored exams for it
    """
    authentication_classes = (SessionAuthenticationAllowInactiveUser,
                              OAuth2AuthenticationAllowInactiveUser)
    permission_classes = ApiKeyHeaderPermissionIsAuthenticated,

    def get(self, request, username):
        result = get_user_proctored_exams(username, request)

        return Response(data=result)


class UpdateVerifiedCohort(APIView, ApiKeyPermissionMixIn):
    """
        **Use Cases**

            Called from plp for all course enrollments updated by user

            1. Add user to verified cohort when updating enrollment to verified mode
            2. Remove user from verified cohort when leaving verified mode

        **Example Requests**:

            POST /api/extended/update_verified_cohort{
                "course_id": "course-v1:edX+DemoX+Demo_Course",
                "username": "john_doe",
                "action": "add"
            }

        **Post Parameters**

            * course_id: The unique identifier for the course.

            * username: The unique user id in plp and edx

            * action: add - add user into verified cohort, delete - remove user from verified cohort 

        **Response Values**

            200 - OK, 400 - Fail (with error message)
    """

    authentication_classes = OAuth2AuthenticationAllowInactiveUser, EnrollmentCrossDomainSessionAuth
    permission_classes = ApiKeyHeaderPermissionIsAuthenticated,

    def post(self, request):
        username = request.data.get('username')
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"message": u"User {username} does not exist".format(username=username)}
            )

        course_id = request.data.get('course_id')
        if not course_id:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"message": u"Course ID must be specified to create a new enrollment."}
            )

        try:
            course_key = CourseKey.from_string(course_id)
        except InvalidKeyError:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={
                    "message": u"No course '{course_id}' found for enrollment".format(course_id=course_id)
                }
            )
        course_is_cohorted = is_course_cohorted(course_key)
        if not course_is_cohorted:
            return Response(
                status=status.HTTP_200_OK,
                data={"message": u"Course {course_id} is not cohorted.".format(course_id=course_id)}
            )

        action = request.data.get('action')
        if action not in [u'add', u'delete']:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"message": u"Available actions are 'add' and 'delete'."}
            )

        cohort_exists = is_cohort_exists(course_key, VERIFIED)
        if not cohort_exists:
            if action == u'add':
                cohort = add_cohort(course_key, VERIFIED, 'manual')
            else:
                return Response(
                    status=status.HTTP_200_OK,
                    data={"message": u"There aren't cohort verified for {course_id}".format(course_id=course_id)}
                )
        else:
            cohort = get_cohort_by_name(course_key, VERIFIED)

        enrollment = CourseEnrollment.objects.get(
            user__username=username, course_id=course_key
        )
        if not enrollment or not enrollment.is_active:
            if action == u'add':
                return Response(
                    status=status.HTTP_400_BAD_REQUEST,
                    data={"message": u"User {username} not enrolled or unenrolled in course {course_id}.".format(
                        username=username,
                        course_id=course_id
                    )}
                )
            if action == u'delete':
                return Response(
                    status=status.HTTP_200_OK,
                    data={"message": u"User {username} not enrolled or unenrolled in course {course_id}.".format(
                        username=username,
                        course_id=course_id
                    )}
                )

        course_cohorts = CourseUserGroup.objects.filter(
            course_id=course_key,
            users__id=user.id,
            group_type=CourseUserGroup.COHORT
        )

        # remove user from verified cohort
        if action == u'delete':
            if not course_cohorts.exists() or course_cohorts[0].name != cohort.name:
                return Response(
                    status=status.HTTP_200_OK,
                    data={"message": u"User {username} already was removed from cohort {cohort_name}".format(
                        username=username,
                        cohort_name=cohort.name
                    )}
                )
            else:
                try:
                    remove_user_from_cohort(cohort, username)
                except ValueError:
                    log.warning(u"User {username} already removed from cohort {cohort_name}".format(
                        username=username,
                        cohort_name=cohort.name
                    ))
                return Response(
                    status=status.HTTP_200_OK,
                    data={"message": u"User {username} removed from cohort {cohort_name}".format(
                        username=username,
                        cohort_name=cohort.name
                    )}
                )

        if course_cohorts.exists():
            if course_cohorts[0] == cohort:
                return Response(
                    status=status.HTTP_200_OK,
                    data={"message": u"User {username} already present in cohort {cohort_name}".format(
                        username=username,
                        cohort_name=cohort.name
                    )}
                )

        add_user_into_verified_cohort(course_cohorts, cohort, user)

        return Response(
            status=status.HTTP_200_OK,
            data={"message": u"User {username} added to cohort {cohort_name}".format(
                username=user.username,
                cohort_name=cohort.name
            )}
        )


def add_user_into_verified_cohort(course_cohorts, cohort, user):
    try:
        add_user_to_cohort(cohort, user.username)
    except ValueError:
        log.warning("User {} already present in the cohort {}".format(user.username, cohort.name))


class Subscriptions(APIView, ApiKeyPermissionMixIn):
    """
        **Use Cases**

            Called from plp when user change subscriptions parameters

            1. Subscribe user to course news
            2. Unsubscribe user to course news

        **Example Requests**:

            POST /api/extended/subscriptions{
                "course_id": "course-v1:edX+DemoX+Demo_Course",
                "username": "john_doe",
                "subscribe": True
            }

        **Post Parameters**

            * course_id: The unique identifier for the course.

            * username: The unique user id in plp and edx

            * do_subscribe: True or False

        **Response Values**

            200 - OK, 400 - Fail (with error message)
    """

    authentication_classes = OAuth2AuthenticationAllowInactiveUser, EnrollmentCrossDomainSessionAuth
    permission_classes = ApiKeyHeaderPermissionIsAuthenticated,

    def post(self, request):
        """Modify user's setting for receiving emails from a course."""
        username = request.data.get('username')
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"message": u"User {username} does not exist".format(username=username)}
            )

        course_id = request.data.get('course_id')
        if not course_id:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"message": u"Course ID must be specified."}
            )

        try:
            course_key = CourseKey.from_string(course_id)
        except InvalidKeyError:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={
                    "message": u"No course '{course_id}' found".format(course_id=course_id)
                }
            )

        receive_emails = request.data.get("subscribe")
        if receive_emails:
            optout_object = Optout.objects.filter(user=user, course_id=course_key)
            if optout_object:
                optout_object.delete()
            log.info(
                u"User %s (%s) opted in to receive emails from course %s",
                user.username,
                user.email,
                course_id
            )
            track_views.server_track(request, "change-email-settings", {"receive_emails": "no", "course": course_id})
        else:
            Optout.objects.get_or_create(user=user, course_id=course_key)
            log.info(
                u"User %s (%s) opted out of receiving emails from course %s",
                user.username,
                user.email,
                course_id
            )
            track_views.server_track(request, "change-email-settings", {"receive_emails": "yes", "course": course_id})
        return Response(status=status.HTTP_200_OK)


class Credentials(APIView, ApiKeyPermissionMixIn):
    """
        **Use Cases**

            Called from sso when collecting non trivial user credentials

            1. Get the dictionary of credentials for users

        **Example Requests**:

            GET /api/extended/credentials

        **Response Values**

            {
                "course_id_1": ["user_1_1", "user_1_2", ... , "user_1_n"],
                ...
                "course_id_m": ["user_m_1", "user_m_2", ... , "user_m_n"],
                "staff":  ["user_staff_1", "user_staff_2", ... , "user_staff_n"] // list of Global Staff users
            }
    """

    authentication_classes = OAuth2AuthenticationAllowInactiveUser,
    permission_classes = ApiKeyHeaderPermissionIsAuthenticated,

    def get(self, request):
        global_staff_users = User.objects.filter(is_staff=True)
        creds = dict()
        creds['staff'] = [u.username for u in global_staff_users]
        creds['discussions'] = dict()
        creds['unenrolled'] = dict()
        for course in modulestore().get_courses():
            course_id = course.id
            instructors = CourseAccessRole.objects.filter(course_id=course_id, role__in=[u'instructor', u'admin', u'staff'])
            creds[course_id.html_id()] = list(set([u.user.username for u in instructors]) - set(creds['staff']))
            ce = CourseEnrollment.objects.filter(course_id=course_id, is_active=True).values_list("user__username", flat=True)
            unenrolled = list(set(creds[course_id.html_id()]) - set(ce))
            if len(unenrolled) > 0:
                creds['unenrolled'][course_id.html_id()] = unenrolled
            roles = Role.objects.exclude(name=FORUM_ROLE_STUDENT).filter(course_id=course_id)
            if roles:
                creds['discussions'][course_id.html_id()] = dict()
                for role in roles:
                    creds['discussions'][course_id.html_id()][role.name] = [u.username for u in role.users.all()]
        return Response(data=creds)


def check_proctored_exams_attempt_turn_on(method):
    """
    Checks that option is turned on
    :param method:
    :return:
    """
    def dummy_api(*args, **kwargs):
        return Response(status=status.HTTP_404_NOT_FOUND)

    if not (ProctoredExamStudentAttempt and settings.FEATURES.get("PROCTORED_EXAMS_ATTEMPT_DELETE", False)):
        return dummy_api
    return method


class ProctoredExamsAttemptView(APIView):
    """
        **Use Cases**

        Allow to delete ExamAttempt for given user


        **Example Requests**:

            DELETE /api/extended/user_proctored_exam_attempt/A9597706-BB17-47A8-84BB-16F779FEB771/{
                "user_id": "1",
            }

        **Post Parameters**

            * user_id: The unique user id in plp and edx


        **Response Values**

            200 - OK, 404 - turned off, 400 - Fail (with error message), 500 - Failed for found user and attempt


    """
    authentication_classes = (SessionAuthenticationAllowInactiveUser,
                              OAuth2AuthenticationAllowInactiveUser)
    permission_classes = ApiKeyHeaderPermission,

    @staticmethod
    def is_allowed_for_session(attempt):
        course_id = attempt.proctored_exam.course_id
        course_key = CourseKey.from_string(course_id)
        try:
            course = modulestore().get_course(course_key)
        except Exception as e:
            logging.error("API get course for id {} error; Traceback:{}".format(course_id, str(e)))
            return False
        return getattr(course, "allow_deleting_proctoring_attempts", False)

    @check_proctored_exams_attempt_turn_on
    def delete(self, request, attempt_code):
        try:
            attempt = ProctoredExamStudentAttempt.objects.get_exam_attempt_by_code(attempt_code)
        except Exception as e:
            logging.error("Wrong proctored exam attempt code: {}; Exception: {}".format(attempt_code, str(e)))
            return Response(data={"message": "Wrong attempt_code"}, status=status.HTTP_400_BAD_REQUEST)

        if not self.is_allowed_for_session(attempt):
            return Response(status=status.HTTP_404_NOT_FOUND)

        try:
            remove_exam_attempt(attempt_id=attempt.id, requesting_user=attempt.user)
        except Exception as e:
            logging.error("Failed to remove proctored exam attempt {}".format(attempt_code))
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(status=200)


class CourseCalendar(APIView, ApiKeyPermissionMixIn):
    """
        **Use Cases**
            Allow to get iCalendar file with course deadlines


        **Example Requests**:

            GET /api/extended/calendar/{course_key_string}/

        **Post Parameters**

            * username: User unique username. Optional. Works only if request.user is staff

        **Response Values**

            200 - iCalendar file, 400 - bad username, 403 - non-staff user requests calendar for other user

    """
    authentication_classes = (SessionAuthenticationAllowInactiveUser,
                              OAuth2AuthenticationAllowInactiveUser)
    permission_classes = ApiKeyHeaderPermissionIsAuthenticated,

    def get(self, request, course_key_string):
        if not settings.FEATURES.get("ICALENDAR_DUE_API", False):
            return Response(status=status.HTTP_404_NOT_FOUND)

        username = request.GET.get("username", None)
        log.info(request.user)
        if username:
            try:
                if request.user.is_staff:
                    user = User.objects.get(username=username)
                else:
                    user = User.objects.get(username=username)
                    #return Response(status=status.HTTP_403_FORBIDDEN,
                    #                data={"message": "Must be staff to request other user's calendar"})
            except:
                return Response(status=status.HTTP_400_BAD_REQUEST, data={"message": "Wrong user id"})
        else:
            user = request.user

        text = get_course_calendar(user, course_key_string)
        mime = "text/calendar"
        response = HttpResponse(text, content_type=mime, status=200)
        response['Content-Disposition'] = 'attachment; filename="{}_calendar.ics"'.format(course_key_string)
        return response
