# dms/admin.py

from django.contrib import admin
from .models import Team, Category, Document, DocumentPermission, Comment, AuditLog, UserProfile, Folder, FolderPermission

@admin.register(Folder)
class FolderAdmin(admin.ModelAdmin):
    list_display = ('name', 'get_full_path', 'owner', 'parent_folder', 'category', 'created_at')
    list_filter = ('category', 'created_at', 'owner')
    search_fields = ('name', 'description')
    raw_id_fields = ('parent_folder', 'owner')
    
    def get_full_path(self, obj):
        return obj.get_full_path()
    get_full_path.short_description = 'Full Path'

@admin.register(FolderPermission)
class FolderPermissionAdmin(admin.ModelAdmin):
    list_display = ('folder', 'user', 'team', 'permission_type', 'inherit_to_subfolders', 'created_at')
    list_filter = ('permission_type', 'inherit_to_subfolders', 'created_at')
    raw_id_fields = ('folder', 'user', 'team')


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ('title', 'owner', 'folder', 'status', 'upload_date', 'version', 'visibility')
    list_filter = ('visibility', 'status', 'upload_date', 'categories')
    search_fields = ('title', 'description', 'tags')
    raw_id_fields = ('folder', 'owner')
    filter_horizontal = ('categories',)

@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at')
    filter_horizontal = ('members',)

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name',)

@admin.register(DocumentPermission)
class DocumentPermissionAdmin(admin.ModelAdmin):
    list_display = ('document', 'user', 'team', 'permission_type', 'created_at')
    list_filter = ('permission_type',)

@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ('document', 'user', 'parent_comment', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('text',)

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action_type', 'target_object', 'timestamp')
    list_filter = ('action_type', 'timestamp')

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'role')
    list_filter = ('role',)
