# dms/forms.py

from django import forms
from django.contrib.auth.models import User
from .models import Document, Comment, Team, Category, UserProfile

class DocumentForm(forms.ModelForm):
    categories = forms.ModelMultipleChoiceField(
        queryset=Category.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=True
    )
    
    tags = forms.CharField(
        required=False, 
        widget=forms.TextInput(attrs={'placeholder': 'Enter tags separated by commas'})
    )
    
    class Meta:
        model = Document
        fields = ['title', 'file', 'description', 'categories', 'tags', 'visibility']
        
class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ['text']
        widgets = {
            'text': forms.Textarea(attrs={'rows': 3}),
        }

class DocumentShareForm(forms.Form):
    teams = forms.ModelMultipleChoiceField(
        queryset=Team.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=False
    )
    
    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=False
    )
    
    PERMISSION_CHOICES = [
        ('RD', 'Read Only'),
        ('CM', 'Read & Comment'),
        ('WR', 'Full Access')
    ]
    
    permission = forms.ChoiceField(choices=PERMISSION_CHOICES)

class UserRegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)
    
    ROLE_CHOICES = [
        (UserProfile.ROLE_CONSULTANT, 'Consultant'),
        (UserProfile.ROLE_OFFICIAL, 'Parliament Official'),
        (UserProfile.ROLE_COMMITTEE, 'Committee Member'),
        (UserProfile.ROLE_TEAM_LEADER, 'Team Leader'),
        (UserProfile.ROLE_TEAM_MEMBER, 'Team Member'),
    ]
    
    role = forms.ChoiceField(choices=ROLE_CHOICES)
    teams = forms.ModelMultipleChoiceField(
        queryset=Team.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=False
    )
    
    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'password']
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        
        if password and confirm_password and password != confirm_password:
            self.add_error('confirm_password', 'Passwords do not match')
        
        return cleaned_data