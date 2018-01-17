import json
from django.db import models


class CourseUserResultCache(models.Model):
    """Caches student's grade_summary"""

    username = models.CharField(max_length=255)
    course_id = models.CharField(max_length=255)
    data = models.TextField()

    @classmethod
    def get_grade_summary(cls, user, course_id):
        try:
            row = cls.objects.get(username=user.username, course_id=course_id)
        except cls.DoesNotExist:
            return None
        return json.loads(row.data)

    @classmethod
    def save_grade_summary(cls, user, course_id, data):
        row, created = cls.objects.get_or_create(username=user.username, course_id=course_id)
        row.data = json.dumps(data)
        row.save()
