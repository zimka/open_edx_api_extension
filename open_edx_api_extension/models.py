import json
import uuid
import logging
from django.db import models

log = logging.getLogger(__name__)


class InstructorTaskExtendedKwargs(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    jsonized_kwargs = models.TextField(blank=False)

    @classmethod
    def get_id_for_kwargs(cls, kwargs_dict):
        if not isinstance(kwargs_dict, dict):
            raise TypeError("'kwargs_dict' must be dict")
        representation = json.dumps(kwargs_dict)
        instance = cls.objects.create(jsonized_kwargs=representation)
        return instance.id

    @classmethod
    def get_kwargs_for_id(cls, id):
        try:
            instance = cls.objects.get(id=id)
            kwargs = json.loads(instance.jsonized_kwargs)
        except cls.DoesNotExist:
            log.error("Tried to get args for hash: '{}'; Doesn't exist.".format(id))
            kwargs = {}
        except ValueError as e:
            log.error("Non-json value in the field 'jsonized_kwargs' :'{}'".format(str(e)))
            kwargs = {}
        return kwargs
