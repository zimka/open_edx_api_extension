import inspect
from functools import wraps

from dirtyfields import DirtyFieldsMixin
from django.dispatch import Signal


def get_model_tracking_mixin(forced_keys):
    """
    Returns mixin that makes model send specific signal every time it's changed.
    Signal contains data that was changed and fields mentioned
    in forced_keys.

    Example:
        class MyUser(get_model_tracking_mixin(forced_keys=("username")), models.Model):
            ...
    """
    class _ChangeTrackingMixin(DirtyFieldsMixin):
        changed_signal = Signal(providing_args=["old_fields", "new_fields", "forced_fields"])

        def save(self, *args, **kwargs):
            old_fields = {}
            if self.pk:
                old_fields = self.get_dirty_fields(check_relationship=True)
            saved = super(_ChangeTrackingMixin, self).save(*args, **kwargs)

            all_keys = [x.name for x in self._meta.get_fields()]
            check_keys = old_fields.keys() if old_fields else all_keys
            new_fields = dict((key,getattr(self, key, None)) for key in check_keys)
            forced_fields = dict((key, getattr(self, key, None)) for key in forced_keys)
            self.changed_signal.send(
                sender=self.__class__,
                forced_fields=forced_fields,
                old_fields=old_fields,
                new_fields=new_fields
            )
            return saved

        def delete(self, *args, **kwargs):
            check_keys = [x.name for x in self._meta.get_fields()]
            old_fields = dict((key,getattr(self, key, None)) for key in check_keys)
            deleted = super(_ChangeTrackingMixin, self).delete(*args, **kwargs)
            forced_fields = dict((key, getattr(self, key, None)) for key in forced_keys)
            self.changed_signal.send(
                sender=self.__class__,
                forced_fields=forced_fields,
                old_fields=old_fields,
                new_fields={}
            )
            return deleted
    return _ChangeTrackingMixin


def track_methods(method_names):
    """
    Decorator for models to make it send specific signal every time method(or classmethod)
    is called. Signal contains method name, args, kwargs and the method result.
    Signal is the same for all methods listed in method_names.
    If method changes it's args/kwargs, signal receiver will get changed version,
    not the one that came into the method

    Example:
        @track_methods(("foobar",))
        class MyUser(models.model):
            ...
    """
    def class_decorator(cls):
        """
        Parameterized class decorator, that replaces all method in method_names
        """
        cls.method_called_signal = Signal(providing_args=["method_name", "args", "kwargs", "result"])

        def signaling_method(method, method_name):
            """
            Method decorator, that makes any method send signal
            """
            is_classmethod = inspect.ismethod(method) and method.__self__ is cls

            @wraps(method)
            def wrapped(*args, **kwargs):
                """
                Method call and signal sending implementation itself
                """
                if is_classmethod:
                    # self should be passed explicitly, while cls is not
                    args = args[1::]
                result = method(*args, **kwargs)
                cls.method_called_signal.send(
                    sender=cls,
                    method_name=method_name,
                    args=args,
                    kwargs=kwargs,
                    result=result
                )
                return result

            if is_classmethod:
                return classmethod(wrapped)
            else:
                return wrapped

        for name in method_names:
            current_method = getattr(cls, name)
            replace_method = signaling_method(current_method, name)
            setattr(cls, name, replace_method)
        return cls
    return class_decorator
