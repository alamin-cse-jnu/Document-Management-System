# dms/forms.py - COMPLETE forms file with all needed forms

from django import forms
from django.contrib.auth.models import User
from .models import Document, Comment, Team, Category, UserProfile, Folder
# Import get_accessible_folders only if utils.py exists
try:
    from .utils import get_accessible_folders
except ImportError:
    # Fallback function if utils.py doesn't exist yet
    def get_accessible_folders(user, category=None):
        if user.profile.role == UserProfile.ROLE_ADMIN:
            if category:
                return Folder.objects.filter(category=category)
            return Folder.objects.all()
        user_teams = user.teams.all()
        if category:
            return Folder.objects.filter(
                Q(category=category) & 
                (Q(owner=user) | Q(owner__teams__in=user_teams))
            ).distinct()
        return Folder.objects.filter(
            Q(owner=user) | Q(owner__teams__in=user_teams)
        ).distinct()

class DocumentForm(forms.ModelForm):
    categories = forms.ModelMultipleChoiceField(
        queryset=Category.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=True
    )
    
    folder = forms.ModelChoiceField(
        queryset=Folder.objects.none(),  # Will be populated dynamically
        required=False,
        empty_label="Select folder (optional)",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    tags = forms.CharField(
        required=False, 
        widget=forms.TextInput(attrs={'placeholder': 'Enter tags separated by commas'})
    )
    
    # NEW: Draft functionality
    save_as_draft = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    
    class Meta:
        model = Document
        fields = ['title', 'file', 'description', 'categories', 'folder', 'tags', 'visibility', 'save_as_draft']
        
    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        category_id = kwargs.pop('category_id', None)
        folder_id = kwargs.pop('folder_id', None)
        super().__init__(*args, **kwargs)
        
        if user:
            # Populate folders user can access
            if category_id:
                try:
                    category = Category.objects.get(id=category_id)
                    accessible_folders = get_accessible_folders(user, category)
                    self.fields['folder'].queryset = accessible_folders
                    
                    # Pre-select category
                    self.fields['categories'].initial = [category]
                except Category.DoesNotExist:
                    pass
            else:
                # Get all accessible folders for the user
                all_accessible_folders = []
                for category in Category.objects.all():
                    folders = get_accessible_folders(user, category)
                    all_accessible_folders.extend(folders)
                self.fields['folder'].queryset = Folder.objects.filter(
                    id__in=[f.id for f in all_accessible_folders]
                )
            
            # Pre-select folder if specified
            if folder_id:
                try:
                    folder = Folder.objects.get(id=folder_id)
                    self.fields['folder'].initial = folder
                    self.fields['categories'].initial = [folder.category]
                except Folder.DoesNotExist:
                    pass
    
    def save(self, commit=True):
        document = super().save(commit=False)
        
        # Set status based on save_as_draft
        if self.cleaned_data.get('save_as_draft'):
            document.status = Document.DOCUMENT_STATUS_DRAFT
        else:
            document.status = Document.DOCUMENT_STATUS_PUBLISHED
            if not document.published_at:
                from django.utils import timezone
                document.published_at = timezone.now()
        
        if commit:
            document.save()
            self.save_m2m()
        
        return document

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
    
    phone_number = forms.CharField(max_length=20, required=False)
    designation = forms.CharField(max_length=100, required=False)
    
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

# NEW FORMS for folder functionality

class FolderForm(forms.ModelForm):
    """Form for creating/editing folders"""
    class Meta:
        model = Folder
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter folder name'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Optional description'}),
        }

class FolderMoveForm(forms.Form):
    """Form for moving folders"""
    new_parent = forms.ModelChoiceField(
        queryset=Folder.objects.none(),
        required=False,
        empty_label="Move to root level",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    def __init__(self, *args, **kwargs):
        folder = kwargs.pop('folder', None)
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        
        if folder and user:
            # Get possible parent folders (excluding self and descendants)
            accessible_folders = get_accessible_folders(user, folder.category)
            possible_parents = []
            
            for f in accessible_folders:
                if f != folder and not folder.is_ancestor_of(f):
                    possible_parents.append(f)
            
            self.fields['new_parent'].queryset = Folder.objects.filter(
                id__in=[f.id for f in possible_parents]
            )

class DocumentMoveForm(forms.Form):
    """Form for moving documents between folders"""
    new_folder = forms.ModelChoiceField(
        queryset=Folder.objects.none(),
        required=False,
        empty_label="Move to category root",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    def __init__(self, *args, **kwargs):
        document = kwargs.pop('document', None)
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        
        if document and user:
            # Get folders in the same categories as the document
            document_categories = document.categories.all()
            accessible_folders = []
            
            for category in document_categories:
                folders = get_accessible_folders(user, category)
                accessible_folders.extend(folders)
            
            self.fields['new_folder'].queryset = Folder.objects.filter(
                id__in=[f.id for f in accessible_folders]
            ).distinct()