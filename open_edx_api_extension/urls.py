from django.conf.urls import url
from django.conf import settings

from open_edx_api_extension import views


urlpatterns = [
    url(r'^courses/$', views.CourseList.as_view()),
    url(r'^courses/proctored$', views.CourseListWithExams.as_view()),
    url(r'^courses/{}/(?P<username>[\W\w]+)/$'.format(settings.COURSE_ID_PATTERN), views.CourseUserResult.as_view()),
    url(r'^enrollment$', views.SSOEnrollmentListView.as_view(), name='courseenrollments'),
    url(r'^user_proctored_exams/(?P<username>[\W\w]+)/$',
        views.ProctoredExamsListView.as_view(), name='user_proctored_exams'),
    url(r'^libraries/$', views.LibrariesList.as_view()),
    url(r'^paid_mass_enrollment$', views.PaidMassEnrollment.as_view()),
    url(r'^update_verified_cohort$', views.UpdateVerifiedCohort.as_view()),
    url(r'^subscriptions$', views.Subscriptions.as_view()),
    url(r'^credentials$', views.Credentials.as_view()),
    url(r'^calculate_grades_csv/{}/$'.format(settings.COURSE_ID_PATTERN),
        views.view_grades_csv_for_users),
    url(r'^users_grade_reports/$', views.UsersGradeReports.as_view()),
]
