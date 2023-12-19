# Generated by Django 4.2.7 on 2023-11-28 08:09

from django.db import migrations, models
import myapp.validators


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='MyModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file', models.FileField(upload_to='your_upload_path/', validators=[myapp.validators.validate_any_extension])),
            ],
        ),
    ]
