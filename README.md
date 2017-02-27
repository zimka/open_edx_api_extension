# open_edx_api_extension

API extension for Open edX 

Installation:
```bash
pip install -e git+https://github.com/raccoongang/open_edx_api_extension.git#egg=open_edx_api_extension
```

Add in file lms/envs/common.py
```python
INSTALLED_APPS = (
    ...
    'open_edx_api_extension',
)
```

Add in file lms/urls.py

```python
urlpatterns = (
    ...
    url(r'^api/extended/', include('open_edx_api_extension.urls', namespace='api_extension')),
)
```

## There are two API endpoints:

### Course list

/api/extended/courses/

NOTE: For use it be sure you set EDX_API_KEY in Open edX LMS environment settings

Example:

```bash
 curl -X GET http://<your.lms.domain>/api/extended/courses/?format=json -H 'X-Edx-Api-Key: edx-api-key'
```

### Course User Results

/api/extended/courses/{course_id}/{username}/

This endpoint uses standard oauth access.


### Enrollments list

/api/extended/enrollment

Get a list of all courses enrollments.
Used EDX_API_KEY for access to this API

See original documentation for other attributes and usage:
http://edx-platform-api.readthedocs.org/en/latest/enrollment/enrollment.html#enrollment.views.EnrollmentView


### User Grade Lists

/api/extended/calculate_grades_csv/$course_id/?usernames=["name1","name2"]

Generates grade lists for given username for given course_id.
You can define custom storage for reports:

```python
CUSTOM_GRADES_DOWNLOAD = {
    'STORAGE_TYPE': 'localfs',
    'BUCKET': 'edx-grades',
    'ROOT_PATH': '/tmp/edx-s3/custom_grades',
}
```