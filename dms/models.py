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

class Folder(models.Model):
    """
    Hierarchical folder structure within categories
    """
    name = models.CharField(max_length=255)
    parent_folder = models.ForeignKey(
        'self', 
        null=True, 
        blank=True, 
        on_delete=models.CASCADE,
        related_name='subfolders'
    )
    category = models.ForeignKey(
        'Category', 
        on_delete=models.CASCADE, 
        related_name='folders'
    )
    owner = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='owned_folders'
    )
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        # Ensure unique folder names within the same parent
        unique_together = ['name', 'parent_folder', 'category']
        ordering = ['name']
    
    def __str__(self):
        return f"{self.get_full_path()}"
    
    def get_full_path(self):
        """Get the full path of the folder"""
        if self.parent_folder:
            return f"{self.parent_folder.get_full_path()}/{self.name}"
        return f"{self.category.name}/{self.name}"
    
    def get_ancestors(self):
        """Get all parent folders up to the root"""
        ancestors = []
        current = self.parent_folder
        while current:
            ancestors.insert(0, current)
            current = current.parent_folder
        return ancestors
    
    def get_descendants(self):
        """Get all subfolders recursively"""
        descendants = []
        for subfolder in self.subfolders.all():
            descendants.append(subfolder)
            descendants.extend(subfolder.get_descendants())
        return descendants
    
    def is_ancestor_of(self, other_folder):
        """Check if this folder is an ancestor of another folder"""
        return self in other_folder.get_ancestors()
    
    def can_be_moved_to(self, new_parent):
        """Check if folder can be moved to new parent (prevent circular references)"""
        if new_parent is None:
            return True
        if new_parent == self:
            return False
        if self.is_ancestor_of(new_parent):
            return False
        return True


class FolderPermission(models.Model):
    """
    Folder-level permissions (similar to DocumentPermission)
    """
    folder = models.ForeignKey(
        Folder, 
        on_delete=models.CASCADE, 
        related_name='permissions'
    )
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True
    )
    team = models.ForeignKey(
        'Team', 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True
    )
    
    # Permission types
    PERMISSION_READ = 'RD'
    PERMISSION_WRITE = 'WR'
    PERMISSION_DELETE = 'DL'
    PERMISSION_MANAGE = 'MG'  # Can create subfolders and manage permissions
    
    PERMISSION_CHOICES = [
        (PERMISSION_READ, 'Read'),
        (PERMISSION_WRITE, 'Write'),
        (PERMISSION_DELETE, 'Delete'),
        (PERMISSION_MANAGE, 'Manage'),
    ]
    
    permission_type = models.CharField(
        max_length=2,
        choices=PERMISSION_CHOICES,
        default=PERMISSION_READ,
    )
    
    inherit_to_subfolders = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        constraints = [
            models.CheckConstraint(
                check=models.Q(user__isnull=False) | models.Q(team__isnull=False),
                name='folder_either_user_or_team_not_null'
            )
        ]
        unique_together = ['folder', 'user', 'team', 'permission_type']

class Document(models.Model):
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to=document_file_path)
    version = models.PositiveIntegerField(default=1)
    description = models.TextField(blank=True)
    categories = models.ManyToManyField(Category, related_name='documents')
    tags = models.CharField(max_length=255, blank=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='documents')
    upload_date = models.DateTimeField(auto_now_add=True)
    
    # NEW: Folder relationship
    folder = models.ForeignKey(
        Folder, 
        null=True, 
        blank=True, 
        on_delete=models.CASCADE,
        related_name='documents'
    )
    
    # NEW: Draft functionality
    DOCUMENT_STATUS_DRAFT = 'DR'
    DOCUMENT_STATUS_PUBLISHED = 'PB'
    
    DOCUMENT_STATUS_CHOICES = [
        (DOCUMENT_STATUS_DRAFT, 'Draft'),
        (DOCUMENT_STATUS_PUBLISHED, 'Published'),
    ]
    
    status = models.CharField(
        max_length=2,
        choices=DOCUMENT_STATUS_CHOICES,
        default=DOCUMENT_STATUS_PUBLISHED,
    )
    published_at = models.DateTimeField(null=True, blank=True)
    
    # Existing visibility choices
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
    
    def get_location_path(self):
        """Get the full path including category and folder"""
        if self.folder:
            return f"{self.folder.get_full_path()}"
        else:
            # If no folder, show category only
            categories = self.categories.all()
            if categories:
                return f"{categories.first().name}/"
            return "Uncategorized/"
    
    def save(self, *args, **kwargs):
        # Set published_at when status changes to published
        if self.status == self.DOCUMENT_STATUS_PUBLISHED and not self.published_at:
            from django.utils import timezone
            self.published_at = timezone.now()
        super().save(*args, **kwargs)

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
    


