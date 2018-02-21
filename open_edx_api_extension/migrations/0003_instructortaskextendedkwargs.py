# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('open_edx_api_extension', '0002_auto_20170621_1316'),
    ]

    operations = [
        migrations.CreateModel(
            name='InstructorTaskExtendedKwargs',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, serialize=False, editable=False, primary_key=True)),
                ('jsonized_kwargs', models.TextField()),
            ],
        ),
    ]
