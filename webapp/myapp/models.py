from django.core.exceptions import ValidationError
from django.db import models
from .validators import validate_any_extension

def validate_file_size(value):
    limit_mb = 32
    if value.size > limit_mb * 1024 * 1024:
        raise ValidationError('*File size must be less than {} MB.*'.format(limit_mb))

class MyModel(models.Model):
    file = models.FileField(upload_to='file', validators=[validate_any_extension, validate_file_size])

