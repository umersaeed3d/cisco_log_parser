from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django import forms
from django.core.exceptions import ValidationError
from difflib import SequenceMatcher


class CustomUserCreationForm(forms.Form):
    first_name = forms.CharField(label='Enter First Name', min_length=3, max_length=10)
    last_name = forms.CharField(label='Enter Last Name', min_length=4, max_length=10)
    username = forms.CharField(label='Enter Username', min_length=4, max_length=150)
    email = forms.EmailField(label='Enter email')
    password1 = forms.CharField(label='Enter password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirm password', widget=forms.PasswordInput)

    def clean_username(self):
        username = self.cleaned_data['username'].lower()
        r = User.objects.filter(username=username)
        if r.count():
            raise  ValidationError("Username already exists")
        return username

    def clean_email(self):
        email = self.cleaned_data['email'].lower()
        r = User.objects.filter(email=email)
        if r.count():
            raise  ValidationError("Email already exists")
        return email

    def password_check(self,passwd):
      
        SpecialSym =['$', '@', '#', '%']
        val = True
        
        if len(passwd) < 6:
            raise ValidationError('length should be at least 6')
            val = False
            
        if len(passwd) > 20:
            raise ValidationError('length should be not be greater than 8')
            val = False
            
        if not any(char.isdigit() for char in passwd):
            raise ValidationError('Password should have at least one numeral')
            val = False
            
        if not any(char.isupper() for char in passwd):
            raise ValidationError('Password should have at least one uppercase letter')
            val = False
            
        if not any(char.islower() for char in passwd):
            raise ValidationError('Password should have at least one lowercase letter')
            val = False
            
        if not any(char in SpecialSym for char in passwd):
            raise ValidationError('Password should have at least one of the symbols $@#')
            val = False
        if val:
            return val

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        max_similarity = 0.7
        email = self.cleaned_data['email'].lower()
        username = self.cleaned_data['username'].lower()

        if password1 and password2 and password1 != password2:
            raise ValidationError("Password don't match")
        
        if SequenceMatcher(a=password1.lower(), b=username.lower()).quick_ratio() > max_similarity:
            raise ValidationError("The password is too similar to the username.")
        if SequenceMatcher(a=password1.lower(), b=email.lower()).quick_ratio() > max_similarity:
            raise ValidationError("The password is too similar to the email.")
        self.password_check(password1)

        return password2

    def save(self, commit=True):
        user = User.objects.create_user(
            self.cleaned_data['username'],
            first_name = self.cleaned_data['first_name'],
            last_name = self.cleaned_data['last_name'],
            email = self.cleaned_data['email'],
            password = self.cleaned_data['password1']
        )
        return user