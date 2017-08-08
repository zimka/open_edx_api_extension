from django.conf import settings
#from django.utils.translation import ugettext as _ #Crash during startup
from xblock.fields import Boolean, Scope
_ = lambda x: x


class _ProctorAttemptDeletingCourseMixin(object):
    """
    Use this class as a mixin for common.lib.xmodule.xmodule.course_module.CourseFields
    to allow proctors deleting exam attempts
    """
    allow_deleting_proctoring_attempts = Boolean(
        display_name=_("Allow proctors deleting user exam attempt"),
        help=_("Enter true or false. When true, proctors can delete attempts."),
        default=False,
        scope=Scope.settings
    )


class _DummyProctorAttemptDeletingCourseMixin(object):
    pass


FEATURES = getattr(settings, "FEATURES", {})
if FEATURES.get("PROCTORED_EXAMS_ATTEMPT_DELETE", False): #Hack to turn off this course option
    ProctorAttemptDeletingCourseMixin = _ProctorAttemptDeletingCourseMixin
else:
    ProctorAttemptDeletingCourseMixin = _DummyProctorAttemptDeletingCourseMixin

