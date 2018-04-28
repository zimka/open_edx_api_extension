from collections import OrderedDict
from rest_framework import serializers
try:
    from rest_framework.fields import SkipField
except ImportError:
    SkipField = Exception
from edx_proctoring.api import get_all_exams_for_course

from course_structure_api.v0.serializers import CourseSerializer


class ExamSerializerField(serializers.Field):
    """ Serializer for examSerializerField"""

    is_proctored = False

    def __init__(self, *args, **kwargs):
        if 'is_proctored' in kwargs:
            self.is_proctored = kwargs.pop('is_proctored')
        return super(ExamSerializerField, self).__init__(*args, **kwargs)

    def to_representation(self, instance, exams):
        """
        Field value -> String.
        """
        result = []
        for exam in exams:
            if exam['is_proctored'] == self.is_proctored:
                result.append(exam)
        return result


class CourseWithExamsSerializer(CourseSerializer):

    proctored_exams = ExamSerializerField(is_proctored=True)
    regular_exams = ExamSerializerField()

    def __init__(self, *args, **kwargs):
        self.include_expired = kwargs.pop("include_expired", False)
        super(CourseWithExamsSerializer, self).__init__(*args, **kwargs)

    def get_image_url(self, course):
        """ Get the course image URL """
        if hasattr(course, 'image_url'):
            return course.image_url
        return super(CourseWithExamsSerializer, self).get_image_url(course)

    def to_representation(self, instance):
        """
        Object instance -> Dict of primitive datatypes.
        """
        specific_proctoring_system = False
        available_proctoring_service = instance.available_proctoring_services.split(',')
        proctoring_system = self.context['request'].GET.get('proctoring_system')
        if len(available_proctoring_service) > 1 and proctoring_system:
            specific_proctoring_system = proctoring_system
        ret = OrderedDict()
        fields = [field for field in self.fields.values() if
                  not field.write_only]
        exams = get_all_exams_for_course(course_id=instance.id, dt_expired=True, proctoring_service=specific_proctoring_system)
        for field in fields:
            try:
                attribute = field.get_attribute(instance)
            except SkipField:
                continue
            except AttributeError:
                if isinstance(field, ExamSerializerField):
                    ret[field.field_name] = field.to_representation(instance,
                                                                    exams)
                continue

            if attribute is None:
                ret[field.field_name] = None
            else:
                ret[field.field_name] = field.to_representation(attribute)

        return ret
