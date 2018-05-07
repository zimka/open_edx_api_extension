from django.conf.urls import url
import views_cms as views


urlpatterns = [
    url(r'^course/$', views.create_or_update_course),
    url(r'^course-rerun/$', views.rerun_course),
    url(r'^course-check/$', views.check_course_exists),
]