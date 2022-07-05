from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from studentsmanager.models import Student


class UserCreateForm(UserCreationForm):
    email = forms.EmailField(required=True, widget=forms.TextInput(attrs={'placeholder': 'Email address'}))
    first_name = forms.CharField(required=True, max_length=150, widget=forms.TextInput(attrs={'placeholder': 'First name'}))
    last_name = forms.CharField(required=True, max_length=150, widget=forms.TextInput(attrs={'placeholder': 'Last name'}))
    username = forms.CharField(required=True, max_length=150, widget=forms.TextInput(attrs={'placeholder': 'Username'}))
    dateofbirth = forms.DateField()

    class Meta:
        model = Student
        fields = ('first_name', 'last_name', 'username', 'email', 'password1', 'password2', 'dateofbirth')

    def __init__(self, *args, **kwargs):
        super(UserCreateForm, self).__init__(*args, **kwargs)
        self.fields['password1'].widget = forms.PasswordInput(
            attrs={'class': 'form-control', 'placeholder': 'Password'})
        self.fields['password2'].widget = forms.PasswordInput(
            attrs={'class': 'form-control', 'placeholder': 'Password confirmation'})