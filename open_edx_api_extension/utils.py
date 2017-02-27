from django.conf import settings
import os

def get_custom_grade_config():
    # Perform the actual upload
    custom_grades_download = hasattr(settings, "CUSTOM_GRADES_DOWNLOAD")
    return "CUSTOM_GRADES_DOWNLOAD" if custom_grades_download else "GRADES_DOWNLOAD"


def store_links_for_user(store, course_id):
        """
        For a given `course_id`, return a list of `(filename, url)` tuples.
        Calls the `url` method of the underlying storage backend. Returned
        urls can be plugged straight into an href
        """
        course_dir = store.path_to(course_id)
        try:
            _, filenames = store.storage.listdir(course_dir)
        except OSError:
            # Django's FileSystemStorage fails with an OSError if the course
            # dir does not exist; other storage types return an empty list.
            return []
        files = [(filename, os.path.join(course_dir, filename)) for filename in filenames]
        files.sort(key=lambda f: store.storage.modified_time(f[1]), reverse=True)
        return [
            (filename, store.storage.url(full_path))
            for filename, full_path in files
        ]
