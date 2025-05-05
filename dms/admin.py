# dms/admin.py

from django.contrib import admin
from .models import Team, Category, Document, DocumentPermission, Comment, AuditLog, UserProfile

@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at')
    filter_horizontal = ('members',)

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name',)

@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ('title', 'owner', 'upload_date', 'version', 'visibility')
    list_filter = ('visibility', 'upload_date', 'categories')
    search_fields = ('title', 'description', 'tags')

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
