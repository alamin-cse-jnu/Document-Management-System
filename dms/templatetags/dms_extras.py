# dms/templatetags/dms_extras.py
from django import template
import os

register = template.Library()

@register.filter
def filename(value):
    """Returns the filename part of a file path"""
    return os.path.basename(value)

@register.filter
def split_tags(value):
    """Splits a comma-separated string of tags"""
    if not value:
        return []
    return [tag.strip() for tag in value.split(',') if tag.strip()]

@register.filter
def get_shared_users(document):
    """
    Returns a list of full names of users who have access to the document.
    This includes:
    1. Direct document permissions to users
    2. Team members from teams that have document permissions
    3. The document owner (not included as they are shown in the 'Uploaded By' column)
    
    Returns a list of full names, ready to be joined with comma.
    """
    from django.contrib.auth.models import User
    from django.db.models import Q
    
    shared_users = []
    
    # Get users with direct permissions
    direct_users = User.objects.filter(
        documentpermission__document=document
    ).distinct()
    
    for user in direct_users:
        if user != document.owner:  # Exclude the owner
            full_name = user.get_full_name() or user.username
            shared_users.append(full_name)
    
    # Get teams with permissions to this document
    teams_with_perms = document.permissions.filter(team__isnull=False).values_list('team', flat=True)
    
    # Get all users in those teams
    team_users = User.objects.filter(
        teams__id__in=teams_with_perms
    ).distinct().exclude(id__in=direct_users.values_list('id', flat=True))  # Exclude users already counted
    
    for user in team_users:
        if user != document.owner:  # Exclude the owner
            full_name = user.get_full_name() or user.username
            shared_users.append(full_name)
    
    # For Team visibility, add team members of owner's teams if not already included
    if document.visibility == 'TM':
        owner_teams = document.owner.teams.all()
        owner_team_members = User.objects.filter(
            teams__in=owner_teams
        ).distinct().exclude(
            id__in=direct_users.values_list('id', flat=True)
        ).exclude(
            id__in=team_users.values_list('id', flat=True)
        )
        
        for user in owner_team_members:
            if user != document.owner:  # Exclude the owner
                full_name = user.get_full_name() or user.username
                shared_users.append(full_name)
    
    return shared_users