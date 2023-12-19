from django import forms
from .models import MyModel
from .validators import validate_any_extension

class MyModelForm(forms.ModelForm):
    class Meta:
        model = MyModel
        fields = ['file']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['file'].validators = [validate_any_extension]