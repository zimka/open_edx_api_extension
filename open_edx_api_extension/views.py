import json
import logging

from django.core.exceptions import ObjectDoesNotExist
from django.conf import settings
from django.http import HttpResponse
from django.db import transaction
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from django.http import JsonResponse

from rest_framework.generics import RetrieveAPIView, ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from bulk_email.models import Optout

from openedx.core.djangoapps.cors_csrf.decorators import ensure_csrf_cookie_cross_domain
from course_modes.models import CourseMode
from course_structure_api.v0 import serializers
from course_structure_api.v0.views import CourseViewMixin
from courseware import courses

from django_comment_common.models import Role, FORUM_ROLE_STUDENT
from openedx.core.djangoapps.embargo import api as embargo_api
from opaque_keys.edx.keys import CourseKey
from opaque_keys import InvalidKeyError
from student.models import User, CourseEnrollment, CourseAccessRole
from xmodule.modulestore.django import modulestore

from openedx.core.djangoapps.course_groups.cohorts import (
    is_course_cohorted, is_cohort_exists, add_cohort, add_user_to_cohort, remove_user_from_cohort, get_cohort_by_name,
    get_cohort_names, get_course_cohorts, CourseCohort
)
from .edx_release import set_course_cohort_settings
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
from lms.djangoapps.instructor.views.api import require_level
from lms.djangoapps.instructor_task.api_helper import AlreadyRunningError
from lms.djangoapps.instructor_task.models import ReportStore

from course_blocks.api import get_course_blocks
from django.contrib.auth import get_user_model


from track import views as track_views

from open_edx_api_extension.serializers import CourseWithExamsSerializer

from .tasks import submit_calculate_grades_csv_users
from .utils import get_custom_grade_config

log = logging.getLogger(__name__)
VERIFIED = 'verified'

try:
    from edx_proctoring.models import ProctoredExamStudentAttempt, ProctoredExamStudentAttemptCustom, ProctoredCourse
    from edx_proctoring.api import remove_exam_attempt, _get_exam_attempt, update_attempt_status
except ImportError:
    ProctoredExamStudentAttempt = None
    ProctoredExamStudentAttemptCustom = None
    ProctoredCourse = None
    _get_exam_attempt = None
    update_attempt_status = None
from .data import get_course_enrollments, get_user_proctored_exams, get_course_calendar
from .models import CourseUserResultCache
from .utils import student_grades, EdxPlpCohortName


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

        if not enrolled_students:
            return Response({
                "error_description": "User is not enrolled for the course",
                "error": "invalid_request"
            })

        course = None
        grade_summaries = []
        for student in enrolled_students:
            # use cache if have any
            saved_info = CourseUserResultCache.get_grade_summary(student, self.course_key)
            if saved_info is not None:
                grade_summaries.append(saved_info)
                continue

            # otherwise get grades elsewhere and save them to cache
            if course is None:
                course = courses.get_course(self.course_key)
            new_info = student_grades(student, course)
            CourseUserResultCache.save_grade_summary(student, self.course_key, new_info)
            grade_summaries.append(new_info)

        student_info = [
            {
                'username': student.username,
                'id': student.id,
                'email': student.email,
                'grade_summary': grade_summaries[num],
                'realname': student.profile.name,
            }
            for num, student in enumerate(enrolled_students)
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

    def get_courses(self):
        return modulestore().get_courses()

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
            results = self.get_courses()

        proctoring_system = self.request.query_params.get('proctoring_system')
        if proctoring_system:
            if 'ITMO' in proctoring_system:
                proctoring_system = 'ITMO'
            results = (course for course in results if
                       proctoring_system in course.available_proctoring_services.split(','))

        # Ensure only course descriptors are returned.
        results = (course for course in results if
                   course.scope_ids.block_type == 'course')


        # Sort the results in a predictable manner.
        v = sorted(results, key=lambda course: unicode(course.id))
        return v

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

    def get_courses(self):
        if ProctoredCourse:
            return ProctoredCourse.fetch_all()
        else:
            return super(CourseListWithExams, self).get_courses()


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

            POST /api/extended/paid_mass_enrollment{
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

    @classmethod
    def as_view(cls, **initkwargs):
        return transaction.non_atomic_requests()(super(cls, cls).as_view(**initkwargs))

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

    @classmethod
    def as_view(cls, **initkwargs):
        return transaction.non_atomic_requests()(super(cls, cls).as_view(**initkwargs))

    def post(self, request):
        username = request.data.get('username')
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist:
            log.error(u"User {username} does not exist".format(username=username))
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"message": u"User {username} does not exist".format(username=username)}
            )

        course_id = request.data.get('course_id')
        if not course_id:
            log.error(u"Course ID must be specified to create a new enrollment.")
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"message": u"Course ID must be specified to create a new enrollment."}
            )

        try:
            course_key = CourseKey.from_string(course_id)
        except InvalidKeyError:
            log.error(u"No course '{course_id}' found for enrollment".format(course_id=course_id))
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={
                    "message": u"No course '{course_id}' found for enrollment".format(course_id=course_id)
                }
            )

        course_is_cohorted = is_course_cohorted(course_key)
        if not course_is_cohorted:
            log.info(u"Course {course_id} is not cohorted.".format(course_id=course_id))
            return Response(
                status=status.HTTP_200_OK,
                data={"message": u"Course {course_id} is not cohorted.".format(course_id=course_id)}
            )

        action = request.data.get('action')
        if action not in [u'add', u'delete']:
            log.error(u"Available actions are 'add' and 'delete'.")
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"message": u"Available actions are 'add' and 'delete'."}
            )

        cohort_exists = is_cohort_exists(course_key, VERIFIED)
        if not cohort_exists:
            if action == u'add':
                log.info(u"Cohort VERIFIED doesn't exist for course {} so let's create it!".format(course_id))
                cohort = add_cohort(course_key, VERIFIED, 'manual')
                log.info(u"Cohort VEIFIED created for the course {}".format(course_id))
            else:
                log.info(u"There aren't cohort verified for {course_id}".format(course_id=course_id))
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
                log.error(u"Failed to add user into verified cohort. User {username} not enrolled or unenrolled in course {course_id}.".format(username=username, course_id=course_id))
                return Response(
                    status=status.HTTP_400_BAD_REQUEST,
                    data={"message": u"User {username} not enrolled or unenrolled in course {course_id}.".format(
                        username=username,
                        course_id=course_id
                    )}
                )
            if action == u'delete':
                if not enrollment:
                    log.info(u"User {username} is not enrolled in course {course_id}. (!!!)".format(username=username, course_id=course_id))
                    return Response(
                        status=status.HTTP_200_OK,
                        data={"message": u"User {username} is not enrolled in course {course_id}. (!!!)".format(
                            username=username,
                            course_id=course_id
                        )}
                    )
                else:
                    log.info(u"User {username} was unenrolled from course {course_id}.".format(username=username, course_id=course_id))
                    return Response(
                        status=status.HTTP_200_OK,
                        data={"message": u"User {username} was unenrolled from course {course_id}.".format(
                            username=username,
                            course_id=course_id
                        )}
                    )

        course_cohorts = CourseUserGroup.objects.filter(
            course_id=course_key,
            users__id=user.id,
            group_type=CourseUserGroup.COHORT
        )

        default_group = None
        for group in CourseUserGroup.objects.filter(course_id=course_key, group_type=CourseUserGroup.COHORT):
            if group.name.lower() == "default" or group.name.lower() == "default group":
                default_group = group
        if not default_group:
            log.info(u"Cohort DEFAULT doesn't exist for course {} so let's create it!".format(course_id))
            default_group = add_cohort(course_key, "Default Group", 'random')
            log.info(u"Cohort 'Default Group' succesfully created for the course {}".format(course_id))

        # remove user from verified cohort and add to default
        if action == u'delete':
            # let's check, that user not already presented into other cohort
            if course_cohorts.exists():
                if course_cohorts.first().name == default_group.name:
                    log.warning(
                        u"User {username} already present into default cohort {cohort_name} in course {course_id}".format(
                            username=username, cohort_name=default_group.name, course_id=course_id))
                    return Response(
                        status=status.HTTP_200_OK,
                        data={
                            "message": u"User {username} already present into default cohort {cohort_name} in course {course_id}".format(
                                username=username,
                                cohort_name=default_group.name,
                                course_id=course_id
                            )}
                    )
                elif course_cohorts.first().name == VERIFIED:
                    try:
                        add_user_to_cohort(default_group, username)
                        log.info(
                            u"User {username} succesfully moved into default cohort {cohort_name} in course {course_id}".format(
                                username=username, cohort_name=default_group.name, course_id=course_id))
                    except ValueError:
                        log.warning(
                            u"User {username} already present into default cohort {cohort_name} in course {course_id}".format(
                                username=username, cohort_name=default_group.name, course_id=course_id))
                    return Response(
                        status=status.HTTP_200_OK,
                        data={
                            "message": u"User {username} moved into default cohort {cohort_name} in course {course_id}".format(
                                username=username,
                                cohort_name=default_group.name,
                                course_id=course_id
                            )}
                    )
                else:
                    log.info(u"Moving user {username} into default cohort {cohort_name} from verified in course {course_id}".format(username=username, cohort_name=default_group.name, course_id=course_id))
                    try:
                        add_user_to_cohort(default_group, username)
                        log.info(u"User {username} succesfully moved into default cohort {cohort_name} in course {course_id}".format(username=username, cohort_name=default_group.name, course_id=course_id))
                    except ValueError:
                        log.warning(u"User {username} already present into default cohort {cohort_name} in course {course_id}".format(username=username, cohort_name=default_group.name, course_id=course_id))

                    return Response(
                        status=status.HTTP_200_OK,
                        data={"message": u"User {username} already present in non-verified cohort {cohort_name} in course {course_id}".format(
                                username=username, cohort_name=course_cohorts.first().name, course_id=course_id
                        )}
                    )
            else:
                add_user_to_cohort(default_group, username)
                log.info(
                    u"User {username} succesfully moved into default cohort {cohort_name} in course {course_id}".format(
                        username=username, cohort_name=default_group.name, course_id=course_id))
                return Response(
                    status=status.HTTP_200_OK,
                    data={
                        "message": u"User {username} moved into default cohort {cohort_name} in course {course_id}".format(
                            username=username,
                            cohort_name=default_group.name,
                            course_id=course_id
                        )}
                )

        if action == u"add":
            message = add_user_into_verified_cohort(course_cohorts, cohort, user)
            if not message:
                message = u"User {username} added to cohort {cohort_name} into course {course_id}".format(username=user.username, cohort_name=cohort.name, course_id=course_id)
            log.info(message)
            return Response(
                status=status.HTTP_200_OK,
                data={"message":message}
            )


def add_user_into_verified_cohort(course_cohorts, cohort, user):
    try:
        add_user_to_cohort(cohort, user.username)
    except ValueError as e:
        log.warning("User {} already present in the cohort {}".format(user.username, cohort.name))
        return str(e)


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

            * subscribe: True or False

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


# TODO: this one is currently deprecated, should be removed later
@transaction.non_atomic_requests
@ensure_csrf_cookie
@require_level('staff')
def view_grades_csv_for_users(request, course_id):
    """
    Example: GET http://edx.local.se:8000/api/extended/calculate_grades_csv/course-v1:test_o+test_n+test_r?usernames=["test","test1"]
    """
    course_key = CourseKey.from_string(course_id)
    try:
        usernames_str = request.GET.get("usernames")
        usernames = json.loads(usernames_str)
    except AttributeError as e:
        logging.error("API extensions, user grades error: {}".format(str(e)))
        return JsonResponse({"status": "An error occured: failed to get usernames from request"})
    try:
        submit_calculate_grades_csv_users(request, course_key, usernames)
        success_status = ("The grade report is being created."
                           " To view the status of the report, see Pending Tasks below.")
        return JsonResponse({"status": success_status})
    except AlreadyRunningError:
        already_running_status = ("The grade report is currently being created."
                                   " To view the status of the report, see Pending Tasks below."
                                   " You will be able to download the report when it is complete.")
        return JsonResponse({"status": already_running_status})


# TODO: this one is currently deprecated, should be removed later
class UsersGradeReports(APIView, ApiKeyPermissionMixIn):
    """
        **Use Cases**

            Used to get reports urls for given course_id and given usenames

        **Example Requests**:

            GET /api/extended/users_grade_reports{
                "course_ids": ["course-v1:edX+DemoX+Demo_Course", ...]
                "usernames": ["test"]
            }

        **Response Values**

            {
                "course_id_1": {"reports":{
                    "username_1_1":[url_report1.csv, ..., url_reportn.csv],
                    "broken_username":"Error: user not found",
                     ...
                    "username_1_n": {...}
                    }
                }
                "broken_course_id":{"error":"No course for this course_id"}
                ...
                "course_id_m": {"reports":{...}}
            }
            OR
            {"error": "<Some fatal error>"}

    """

    #authentication_classes = OAuth2AuthenticationAllowInactiveUser,
    #permission_classes = ApiKeyHeaderPermissionIsAuthenticated,

    def get(self, request):
        #collect data
        data_get = dict(request.GET.iterlists())
        def unjson(s):
            try:
                return json.loads(s)
            except:
                return s

        try:
            usernames = (data_get.get("usernames"))
            usernames = unjson(usernames)
            if isinstance(usernames,unicode):
                usernames = [usernames]
        except Exception as e:
            logging.error("API got incorrect usernames: {}".format(str(e)))
            return Response(data={"error": "Given usenames are incorrect"})

        try:
            course_ids = (data_get.get("course_ids"))
            course_ids = unjson(course_ids)
            if isinstance(course_ids, unicode):
                course_ids = [course_ids]
        except Exception as e:
            logging.error("API got incorrect course_ids: {}".format(str(e)))
            return Response(data={"error": "Given usenames incorrect; Exception:{}".format(str(e))})

        #check existance of users from usernames
        users = User.objects.filter(username__in=usernames)
        users_dict = dict((u.username, u.id) for u in users)
        if not users_dict:
            return Response(data={"error": "No user for any of given usernames"})
        id_user_map = dict((users_dict[x], x) for x in users_dict)
        users_not_found = [uname for uname in usernames if uname not in users_dict]
        if users_not_found:
            msg = "Requested users not found: {}".format(",".join(users_not_found))
            logging.error(msg)
        users_dict.update({(uname, None) for uname in users_not_found})

        #check existance of courses from course_ids
        course_ids_dict = {}
        for cid in course_ids:
            try:
                ckey = CourseKey.from_string(cid)
                course_ids_dict[cid] = ckey
            except:
                logging.error("No course for course_id given to API: {}".format(cid))
                course_ids_dict[cid] = None
                continue
        if not [cid for cid in course_ids if course_ids_dict[cid]]:
            return Response(data={"error": "No course for any of given course_ids"})

        answer_data = dict((cid, {}) for cid in course_ids_dict)
        report_store = ReportStore.from_config(config_name=get_custom_grade_config())
        for cid in course_ids_dict:
            if not course_ids_dict[cid]:
                answer_data[cid] = {"error":"No course for this course_id"}
                continue
            file_urls = report_store.links_for(course_ids_dict[cid])
            current_reports = {}
            for uname in users_dict:
                if users_dict[uname]:
                    current_reports[uname] = []
                else:
                    current_reports[uname] = "Error: user not found"

            for name, url in file_urls:
                name_parts = name.split("_")
                url_id = int(name_parts[name_parts.index('id') + 1])
                url_uname = id_user_map.get(url_id, None) # None means this user wasn't requested
                if url_uname:
                    current_reports[url_uname].append(url)
            answer_data[cid] = {"reports":current_reports}
        return Response(data=answer_data)


class CalculateUsersGradeReport(APIView):
    """
        **Use Cases**

            Allows to request grading list calculation for course it against
            listed users. When task finished, it notifies client on given
            callback url about the result.
            Requires apllication/json content-type


        **Example Requests**:

            POST /api/extended/calculate_grade_reports{
                "course_id": "course-v1:edX+DemoX+Demo_Course"
                "users": ["test", "test2"],
                "staff_username": "instructor_username",
                "callback_url": "plp.npoed.ru/grade_handle/"
            }

        **Response Values**

            200: if task is taken in processing

            400: {"error": "<Error description>"}if error occurred

    """
    authentication_classes = OAuth2AuthenticationAllowInactiveUser, SessionAuthenticationAllowInactiveUser
    permission_classes = ApiKeyHeaderPermissionIsAuthenticated,

    @classmethod
    def as_view(cls, **initkwargs):
        """Run as_view() non_atomic"""
        return transaction.non_atomic_requests()(super(cls, cls).as_view(**initkwargs))

    def post(self, request):
        staff_username = request.data.get('staff_username')
        try:
            request.user = User.objects.get(username=staff_username)
        except User.DoesNotExist:
            return JsonResponse({"error": "Bad staff username:'{}'".format(staff_username)}, status=status.HTTP_400_BAD_REQUEST)
        usernames = request.data.get('users', None)
        if usernames is None:
            return JsonResponse({"error": "No users in request"}, status=status.HTTP_400_BAD_REQUEST)
        callback_url = request.data.get('callback_url', None)
        if not callback_url:
            return JsonResponse({"error": "No callback_url in request"}, status=status.HTTP_400_BAD_REQUEST)

        # TODO: better make it part of url scheme
        course_id = request.data.get('course_id')
        if not course_id:
            return JsonResponse({"error": "No course_id in request"}, status=status.HTTP_400_BAD_REQUEST)

        course_key = CourseKey.from_string(course_id)
        if not modulestore().has_course(course_key):
            return JsonResponse(
                {"error": "course with id {} not found".format(course_id)},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            submit_calculate_grades_csv_users(request, course_key, usernames, callback_url)
            return JsonResponse({"status": "Started"})
        except AlreadyRunningError:
            return JsonResponse({"status": "AlreadyRunning"})


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


class AttemptStatuses(APIView):
    """
        **Use Cases**
            This endpoint is called by a 3rd party proctoring review service to determine
            status of an exam attempts.


        **Example Requests**:

            POST /api/extended/edx_proctoring/proctoring_poll_statuses_attempts/

        **Post Parameters**

            * JSON body in format {'attempts': ['<code_1>', '<code_2>', ... , '<code_n>']}

        **Response Values**

            200 - JSON response in format: {'<code_1>': '<status_1>', ..., '<code_n>': '<status_n>'}

    """

    def post(self, request):
        """
        Returns the statuses of an exam attempts.
        Similar to the /api/edx_proctoring/proctoring_poll_status/<attempt_code> but for more than 1 attempt_code.
        """

        try:
            posted_data = json.loads(request.body.decode('utf-8'))
            attempts_codes = posted_data.get('attempts')
            if not isinstance(attempts_codes, list):
                raise ValueError("'attempts' value in JSON request must be list")
            if not attempts_codes:
                raise ValueError("'attempts' list is empty")
        except (ValueError, KeyError) as e:
            return HttpResponse(
                content='Invalid request body.',
                status=400
            )

        attempts_dict = {attempt_code: None for attempt_code in attempts_codes}
        attempts = ProctoredExamStudentAttempt.objects.filter(attempt_code__in=attempts_codes)
        for attempt in attempts:
            exam_attempt = _get_exam_attempt(attempt)
            attempts_dict[attempt.attempt_code] = exam_attempt['status'] if exam_attempt else None

        attempt_custom_status_check = [attempt_code for attempt_code, attempt_status in attempts_dict.iteritems()
                                       if attempt_status is None]
        if attempt_custom_status_check:
            attempts = ProctoredExamStudentAttemptCustom.objects.filter(attempt_code__in=attempt_custom_status_check)
            for attempt in attempts:
                attempts_dict[attempt.attempt_code] = attempt.status

        log.info("Attempts statuses: {}".format(unicode(attempts_dict)))
        return Response(
            data=attempts_dict,
            status=200
        )


class AttemptsBulkUpdate(APIView):
    """
        **Use Cases**
            This endpoint is called by a 3rd party proctoring review service to update group of attempts.


        **Example Requests**:

            POST /api/extended/edx_proctoring/attempts_bulk_update/

        **Post Parameters**

            * JSON body in format
               {'attempts': [
                   {'code': '<code_1>', 'user_id': '<user_id_1>', 'new_status': '<new_status_1>'},
                   ...
                   {'code': '<code_n>', 'user_id': '<user_id_n>', 'new_status': '<new_status_n>'}
               ]}

        **Response Values**

            200 - JSON response in format:
            {
             '<code_1>': {'status': '<new_status_1>'},
             ...
             '<code_n>': {'status': '<new_status_n>'}
            }

    """

    permission_classes = (ApiKeyHeaderPermissionIsAuthenticated,)

    def post(self, request):
        """
        Returns the statuses of an exam attempts.
        """

        try:
            posted_data = json.loads(request.body.decode('utf-8'))
            attempts = posted_data.get('attempts')
            if not isinstance(attempts, list):
                raise ValueError("'attempts' value in JSON request must be list")
            if not attempts:
                raise ValueError("'attempts' list is empty")
        except (ValueError, KeyError) as e:
            return HttpResponse(
                content='Invalid request body.',
                status=400
            )

        result = {}
        attempts_dict = {attempt['code']: attempt for attempt in attempts}
        attempts = ProctoredExamStudentAttempt.objects.filter(attempt_code__in=attempts_dict.keys())
        for attempt in attempts:
            user_id = attempts_dict[attempt.attempt_code]['user_id']
            new_status = attempts_dict[attempt.attempt_code]['new_status']

            try:
                update_attempt_status(attempt.proctored_exam_id, user_id, new_status)
                result[attempt.attempt_code] = {'status': new_status}
            except Exception, e:
                log.info("Exception during update status (new status '{}') for user_id={} attempt_id={}: {}"
                         .format(unicode(new_status), unicode(user_id), unicode(attempt.id), unicode(e)))
                result[attempt.attempt_code] = {'status': attempt.status}

        log.info("New attempts statuses after update: {}".format(unicode(result)))

        return Response(
            data=result,
            status=200
        )


class CohortValidationMixin(object):

    @staticmethod
    def is_bad_course_id(course_id, check_cohorts_enabled=True):
        try:
            course_key = CourseKey.from_string(course_id)
        except (InvalidKeyError, AttributeError) as e:
            return True

        if not modulestore().has_course(course_key):
            return "course with id {} not found".format(course_id)

        if not check_cohorts_enabled:
            return

        if not is_course_cohorted(course_key):
            return "cohorts disabled for course with id {}".format(course_id)


class CourseCohortNames(CohortValidationMixin, APIView):
    """
        **Use Cases**

            Allows to get names of course cohorts if they are enabled for course

        **Example Requests**:

            GET /api/extended/cohorts/cohort_names

        **Get Parameters**

            * course_id: The unique identifier for the course.

        **Response Values**

            400 - bad course_id or absent,

            400 - {"error": "<message>"}

            200 - {"cohorts": [
                                  {"name":"cohort_name1", "mode":"honor"},
                                  {"name":"cohort_name2", "mode":"verified"},
                                  ...
                              ]
                  }

    """

    authentication_classes = OAuth2AuthenticationAllowInactiveUser, SessionAuthenticationAllowInactiveUser
    permission_classes = ApiKeyHeaderPermissionIsAuthenticated,

    def get(self, request):
        course_id = request.query_params.get('course_id')
        message = self.is_bad_course_id(course_id)
        if message:
            data = {"error": message} if isinstance(message, basestring) else {}
            return Response(data=data, status=status.HTTP_400_BAD_REQUEST)

        course = modulestore().get_course(CourseKey.from_string(course_id))
        cohorts_names = get_cohort_names(course)
        plp_names = [EdxPlpCohortName.from_edx(name) for name in cohorts_names.values()]
        plp_names = filter(lambda x: not x.is_hidden, plp_names)
        return Response(data={
            "cohorts": [x.plp_dict for x in plp_names]
        })


class CourseCohortsWithStudents(CohortValidationMixin, APIView):
    """
        **Use Cases**

            Allows to get cohorts with listed users or set
            Post requires apllication/json content-type

        **Example Requests**:

            GET  /api/extended/cohorts/cohorts_with_students/

            POST /api/extended/cohorts/cohorts_with_students/

        **Get Parameters**

            * course_id: The unique identifier for the course.

        **Get Response Values**

            400 - bad course_id or absent,

            400 - {"error": "<message>"}

            200 - {"cohorts": [
                                  {"name":"cohort_name1", "mode":"honor", "usernames": ["name1", "name2", ...]},
                                  {"name":"cohort_name2", "mode":"verified", "usernames": []},
                                  ...
                              ]
                  }

        **Post Parameters**

            Application/json content-type

            * course_id: The unique identifier for the course.

            * mode: honor/verified

            * cohorts: {"cohort_name1": ["user1",...], "cohort_name2": ...}

        **Post Response Values**

            400 - bad course_id or absent,

            400 - {"error": "<message>"}

            400 - {"failed":[
                            {"username":"username1", "cohort":"cohort_name2", "error":"<reason>"},
                            ...
                  ]}

            200 - Ok
    """
    authentication_classes = OAuth2AuthenticationAllowInactiveUser, SessionAuthenticationAllowInactiveUser
    permission_classes = ApiKeyHeaderPermissionIsAuthenticated,

    @classmethod
    def as_view(cls, **initkwargs):
        return transaction.non_atomic_requests()(super(cls, cls).as_view(**initkwargs))

    def get(self, request):
        course_id = request.query_params.get('course_id')
        message = self.is_bad_course_id(course_id)
        if message:
            data = {"error": message} if isinstance(message, basestring) else {}
            return Response(data=data, status=status.HTTP_400_BAD_REQUEST)

        course = modulestore().get_course(CourseKey.from_string(course_id))
        cohorts = get_course_cohorts(course)
        data = []
        for group in cohorts:
            name = group.name
            users = [u.username for u in group.users.all()]
            plp_name = EdxPlpCohortName.from_edx(name)
            if plp_name.is_hidden:
                continue
            plp_dict = plp_name.plp_dict
            plp_dict["usernames"] = users
            data.append(plp_dict)
        return Response(data={"cohorts": data})

    def post(self, request):
        course_id = request.data.get('course_id')
        message = self.is_bad_course_id(course_id, check_cohorts_enabled=False)
        if message:
            data = {"error": message} if isinstance(message, basestring) else {}
            return Response(data=data, status=status.HTTP_400_BAD_REQUEST)
        course_key = CourseKey.from_string(course_id)
        if not is_course_cohorted(course_key):
            set_course_cohort_settings(course_key, is_cohorted=True)

        cohorts_dict = request.data.get('cohorts')
        if not isinstance(cohorts_dict, dict):
            return Response(status=status.HTTP_400_BAD_REQUEST)

        mode = request.data.get('mode')
        try:
            requested_cohorts = [EdxPlpCohortName.from_plp(name, mode) for name in cohorts_dict]
        except ValueError as e:
            return Response(data={"error": unicode(e)})
        need_groups = [x.edx_name for x in requested_cohorts]

        course = modulestore().get_course(course_key)
        have_groups = get_cohort_names(course).values()
        create_groups = set(need_groups) - set(have_groups)
        for name in create_groups:
            # TODO: can it raise with bad name?
            add_cohort(course_key, name, assignment_type=CourseCohort.MANUAL)
            log.info(u"Cohort '{}' for course '{}' was created".format(name, course_key))

        errors = []
        for group in requested_cohorts:
            usernames = cohorts_dict[group.plp_name]
            cohort = get_cohort_by_name(course_key, group.edx_name)
            for u in usernames:
                try:
                    add_user_to_cohort(cohort, u)
                    log.info(u"User '{}' was enrolled at cohort '{}'".format(u, group.edx_name))
                except ValueError:
                    # 'add_user_to_cohort' raises ValueError when user is already present in cohort, but it's ok
                    pass
                except User.DoesNotExist as e:
                    error = {"username": u, "cohort": group.plp_name, "error": unicode(e)}
                    errors.append(error)
                    log.error(u"{}: {}".format(error['error'], error['username']))
        if errors:
            return Response(data={"failed": errors}, status=status.HTTP_400_BAD_REQUEST)
        return Response()

class CourseStructure(APIView):
    """
        **Use Cases**

            Allows to get course structure

        **Example Requests**:

            GET  /api/extended/course_structure

        **Get Parameters**

            * course_id: The unique identifier for the course.

        **Get Response Values**

            400 - bad course_id or absent,

            200 - {"course_id": "course-v1:...",
                   "structure": [
                                  {"chapter_key":"...", "section_key":"...","vertical_key":"...","ckey":"...","chapter_name":"..."},
                                  ...
                              ]
                  }
    """
    authentication_classes = OAuth2AuthenticationAllowInactiveUser, SessionAuthenticationAllowInactiveUser
    permission_classes = ApiKeyHeaderPermissionIsAuthenticated,

    @classmethod
    def as_view(cls, **initkwargs):
        return transaction.non_atomic_requests()(super(cls, cls).as_view(**initkwargs))

    def get(self, request):
        def get_course_by_id(course_id):
            try:
                course_key = CourseKey.from_string(course_id)
            except (InvalidKeyError, AttributeError) as e:
                return None

            if not modulestore().has_course(course_key):
                return None

            return modulestore().get_course(course_key)

        def get_course_structure(course):
            User = get_user_model()
            student = User.objects.filter(is_superuser=True).first()
            return get_course_blocks(student, course.location)


        course = get_course_by_id(request.query_params.get('course_id'))
        if not course:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        response = {
            "course_id": unicode(course.id),
            "structure": [],
        }

        course_structure = get_course_structure(course)
        for chapter_key in course_structure.get_children(course_structure.root_block_usage_key):
            chapter_name = modulestore().get_item(chapter_key).display_name
            for section_key in course_structure.get_children(chapter_key):
                for vertical_key in course_structure.get_children(section_key):
                    for ckey in course_structure.get_children(vertical_key):
                        response["structure"].append({
                            "chapter_key":  unicode(chapter_key),
                            "section_key":  unicode(section_key),
                            "vertical_key": unicode(vertical_key),
                            "ckey":         unicode(ckey),
                            "chapter_name": unicode(chapter_name),
                        })

        return Response(data=response)
