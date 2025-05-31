from django import forms
from django.core.validators import EmailValidator

class RegisterForm(forms.Form):
    username = forms.CharField(max_length=150, required=True)
    email = forms.CharField(max_length=254, required=True, validators=[EmailValidator()])
    password = forms.CharField(widget=forms.PasswordInput, min_length=8, required=True)
    confirm_password = forms.CharField(widget=forms.PasswordInput, required=True)

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError("Passwords do not match.")
        return cleaned_data
    
class LoginForm(forms.Form):
    username = forms.CharField(max_length=150, required=True)
    password = forms.CharField(widget=forms.PasswordInput, required=True)

class NoteForm(forms.Form):
    content = forms.CharField(widget=forms.Textarea, required=True, label='Note')
    