# dms/models.py

from django.db import models
from django.contrib.auth.models import User
import uuid
import os

def document_file_path(instance, filename):
    """Generate file path for new document"""
    ext = filename.split('.')[-1]
    filename = f'{uuid.uuid4()}.{ext}'
    return os.path.join('uploads/documents/', filename)

class Team(models.Model):
    name = models.CharField(max_length=100)
    members = models.ManyToManyField(User, related_name='teams')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name

class Category(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name_plural = "Categories"

class Document(models.Model):
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to=document_file_path)
    version = models.PositiveIntegerField(default=1)
    description = models.TextField(blank=True)
    categories = models.ManyToManyField(Category, related_name='documents')
    tags = models.CharField(max_length=255, blank=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='documents')
    upload_date = models.DateTimeField(auto_now_add=True)
    
    # Visibility choices
    VISIBILITY_PRIVATE = 'PR'
    VISIBILITY_TEAM = 'TM'
    VISIBILITY_PUBLIC = 'PB'
    
    VISIBILITY_CHOICES = [
        (VISIBILITY_PRIVATE, 'Private'),
        (VISIBILITY_TEAM, 'Team Only'),
        (VISIBILITY_PUBLIC, 'Public'),
    ]
    
    visibility = models.CharField(
        max_length=2,
        choices=VISIBILITY_CHOICES,
        default=VISIBILITY_PRIVATE,
    )
    
    def __str__(self):
        return self.title

class DocumentPermission(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='permissions')
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    team = models.ForeignKey(Team, on_delete=models.CASCADE, null=True, blank=True)
    
    # Permission types
    PERMISSION_READ = 'RD'
    PERMISSION_WRITE = 'WR'
    PERMISSION_COMMENT = 'CM'
    PERMISSION_SHARE = 'SH'
    
    PERMISSION_CHOICES = [
        (PERMISSION_READ, 'Read'),
        (PERMISSION_WRITE, 'Write'),
        (PERMISSION_COMMENT, 'Comment'),
        (PERMISSION_SHARE, 'Share'),
    ]
    
    permission_type = models.CharField(
        max_length=2,
        choices=PERMISSION_CHOICES,
        default=PERMISSION_READ,
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        constraints = [
            models.CheckConstraint(
                check=models.Q(user__isnull=False) | models.Q(team__isnull=False),
                name='either_user_or_team_not_null'
            )
        ]

class Comment(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    parent_comment = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE, related_name='replies')
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Comment by {self.user.username} on {self.document.title}"

class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    
    ACTION_UPLOAD = 'UP'
    ACTION_DOWNLOAD = 'DN'
    ACTION_VIEW = 'VW'
    ACTION_EDIT = 'ED'
    ACTION_SHARE = 'SH'
    ACTION_DELETE = 'DL'
    
    ACTION_CHOICES = [
        (ACTION_UPLOAD, 'Upload'),
        (ACTION_DOWNLOAD, 'Download'),
        (ACTION_VIEW, 'View'),
        (ACTION_EDIT, 'Edit'),
        (ACTION_SHARE, 'Share'),
        (ACTION_DELETE, 'Delete'),
    ]
    
    action_type = models.CharField(
        max_length=2,
        choices=ACTION_CHOICES,
    )
    
    target_object = models.CharField(max_length=255)  # Document ID or other object identifier
    details = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.get_action_type_display()} by {self.user.username} at {self.timestamp}"

# Just showing the updated UserProfile model - the rest of models.py remains unchanged

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    ROLE_ADMIN = 'AD'
    ROLE_CONSULTANT = 'CO'
    ROLE_OFFICIAL = 'OF'
    ROLE_COMMITTEE = 'CM'
    ROLE_TEAM_LEADER = 'TL'
    ROLE_TEAM_MEMBER = 'TM'
    
    ROLE_CHOICES = [
        (ROLE_ADMIN, 'Admin'),
        (ROLE_CONSULTANT, 'Consultant'),
        (ROLE_OFFICIAL, 'Parliament Official'),
        (ROLE_COMMITTEE, 'Committee Member'),
        (ROLE_TEAM_LEADER, 'Team Leader'),
        (ROLE_TEAM_MEMBER, 'Team Member'),
    ]
    
    role = models.CharField(
        max_length=2,
        choices=ROLE_CHOICES,
        default=ROLE_TEAM_MEMBER,
    )
    
    # New fields for phone number and designation
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    designation = models.CharField(max_length=100, blank=True, null=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.get_role_display()}"