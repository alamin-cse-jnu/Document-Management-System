from django.contrib.auth.models import User
from django.db.models import Q
from .models import Folder, FolderPermission, Document, UserProfile

def has_folder_permission(user, folder, permission_type):
    """
    Check if user has specific permission on a folder
    Admin can do anything anywhere
    """
    # Admin override - can do anything
    if user.profile.role == UserProfile.ROLE_ADMIN:
        return True
    
    # Owner can do anything with their folder
    if folder.owner == user:
        return True
    
    # Check direct permissions on this folder
    user_teams = user.teams.all()
    
    # Check for direct permission
    direct_permission = FolderPermission.objects.filter(
        folder=folder,
        permission_type=permission_type
    ).filter(
        Q(user=user) | Q(team__in=user_teams)
    ).exists()
    
    if direct_permission:
        return True
    
    # Check inherited permissions from parent folders
    ancestors = folder.get_ancestors()
    for ancestor in reversed(ancestors):  # Check from top to bottom
        inherited_permission = FolderPermission.objects.filter(
            folder=ancestor,
            permission_type=permission_type,
            inherit_to_subfolders=True
        ).filter(
            Q(user=user) | Q(team__in=user_teams)
        ).exists()
        
        if inherited_permission:
            return True
    
    # For read permission, also check team membership with folder owner
    if permission_type == FolderPermission.PERMISSION_READ:
        # If folder owner is in same team, allow read
        owner_teams = folder.owner.teams.all()
        common_teams = user_teams.filter(id__in=owner_teams.values_list('id', flat=True))
        if common_teams.exists():
            return True
    
    return False

def get_accessible_folders(user, category=None):
    """
    Get all folders that user can access (read permission)
    """
    if user.profile.role == UserProfile.ROLE_ADMIN:
        # Admin can see all folders
        if category:
            return Folder.objects.filter(category=category)
        return Folder.objects.all()
    
    # For regular users, get folders they can access
    user_teams = user.teams.all()
    
    # Base queryset
    if category:
        base_queryset = Folder.objects.filter(category=category)
    else:
        base_queryset = Folder.objects.all()
    
    # Folders the user owns
    owned_folders = base_queryset.filter(owner=user)
    
    # Folders owned by teammates (basic team access)
    team_folders = base_queryset.filter(owner__teams__in=user_teams).exclude(owner=user)
    
    # Folders with explicit permissions
    permitted_folder_ids = FolderPermission.objects.filter(
        Q(user=user) | Q(team__in=user_teams),
        permission_type__in=[
            FolderPermission.PERMISSION_READ,
            FolderPermission.PERMISSION_WRITE,
            FolderPermission.PERMISSION_DELETE,
            FolderPermission.PERMISSION_MANAGE
        ]
    ).values_list('folder_id', flat=True)
    
    permitted_folders = base_queryset.filter(id__in=permitted_folder_ids)
    
    # Combine all accessible folders
    accessible_folders = (owned_folders | team_folders | permitted_folders).distinct()
    
    return accessible_folders

def get_folder_tree(user, category):
    """
    Get folder tree structure that user can access
    """
    accessible_folders = get_accessible_folders(user, category)
    
    # Build tree structure
    tree = []
    folder_dict = {}
    
    # Create folder dictionary
    for folder in accessible_folders:
        folder_dict[folder.id] = {
            'folder': folder,
            'children': []
        }
    
    # Build tree
    for folder in accessible_folders:
        if folder.parent_folder and folder.parent_folder.id in folder_dict:
            folder_dict[folder.parent_folder.id]['children'].append(folder_dict[folder.id])
        else:
            # Root level folder
            tree.append(folder_dict[folder.id])
    
    return tree

def can_create_folder_in(user, parent_folder=None, category=None):
    """
    Check if user can create a folder in the specified location
    """
    # Admin can create anywhere
    if user.profile.role == UserProfile.ROLE_ADMIN:
        return True
    
    if parent_folder:
        # Check if user has manage permission on parent folder
        return has_folder_permission(user, parent_folder, FolderPermission.PERMISSION_MANAGE) or \
               has_folder_permission(user, parent_folder, FolderPermission.PERMISSION_WRITE)
    elif category:
        # For root level folders, allow team leaders and above
        return user.profile.role in [
            UserProfile.ROLE_ADMIN, 
            UserProfile.ROLE_TEAM_LEADER,
            UserProfile.ROLE_OFFICIAL
        ]
    
    return False

def get_documents_in_folder(user, folder, include_subfolders=False):
    """
    Get documents in a folder that user can access
    """
    if include_subfolders:
        # Get all descendant folders
        descendant_folders = [folder] + folder.get_descendants()
        accessible_folders = [f for f in descendant_folders if has_folder_permission(user, f, FolderPermission.PERMISSION_READ)]
        documents = Document.objects.filter(folder__in=accessible_folders, status=Document.DOCUMENT_STATUS_PUBLISHED)
    else:
        if not has_folder_permission(user, folder, FolderPermission.PERMISSION_READ):
            return Document.objects.none()
        documents = Document.objects.filter(folder=folder, status=Document.DOCUMENT_STATUS_PUBLISHED)
    
    # Additional document-level permission checking
    user_teams = user.teams.all()
    
    # Filter documents based on visibility and permissions
    accessible_documents = documents.filter(
        Q(owner=user) |  # Documents owned by user
        Q(visibility=Document.VISIBILITY_PUBLIC) |  # Public documents
        (Q(visibility=Document.VISIBILITY_TEAM) &   # Team documents where user is a member
         Q(owner__teams__in=user_teams)) |
        Q(permissions__user=user) |  # Direct permissions
        Q(permissions__team__in=user_teams)  # Team permissions
    ).distinct()
    
    return accessible_documents

def can_user_access_document(user, document):
    """
    Check if user can access a specific document
    """
    # Admin can access everything
    if user.profile.role == UserProfile.ROLE_ADMIN:
        return True
    
    # Owner can access their documents
    if document.owner == user:
        return True
    
    # Check document visibility
    if document.visibility == Document.VISIBILITY_PUBLIC:
        return True
    
    user_teams = user.teams.all()
    
    # Team visibility - check if user is in same team as owner
    if document.visibility == Document.VISIBILITY_TEAM:
        owner_teams = document.owner.teams.all()
        if user_teams.filter(id__in=owner_teams.values_list('id', flat=True)).exists():
            return True
    
    # Check document permissions
    has_permission = document.permissions.filter(
        Q(user=user) | Q(team__in=user_teams)
    ).exists()
    
    if has_permission:
        return True
    
    # Check folder permissions if document is in a folder
    if document.folder:
        return has_folder_permission(user, document.folder, FolderPermission.PERMISSION_READ)
    
    return False
    # Admin can create anywhere
    if user.profile.role == UserProfile.ROLE_ADMIN:
        return True
    
    if parent_folder:
        # Check if user has manage permission on parent folder
        return has_folder_permission(user, parent_folder, FolderPermission.PERMISSION_MANAGE)
    elif category:
        # For root level folders, user needs to be team member or have explicit permission
        # This depends on your business rules - you might want to restrict this
        return True  # For now, allow anyone to create root folders
    
    return False

def get_documents_in_folder(user, folder, include_subfolders=False):
    """
    Get documents in a folder that user can access
    """
    if include_subfolders:
        # Get all descendant folders
        descendant_folders = [folder] + folder.get_descendants()
        accessible_folders = [f for f in descendant_folders if has_folder_permission(user, f, FolderPermission.PERMISSION_READ)]
        documents = Document.objects.filter(folder__in=accessible_folders, status=Document.DOCUMENT_STATUS_PUBLISHED)
    else:
        if not has_folder_permission(user, folder, FolderPermission.PERMISSION_READ):
            return Document.objects.none()
        documents = Document.objects.filter(folder=folder, status=Document.DOCUMENT_STATUS_PUBLISHED)
    
    # Additional document-level permission checking can be added here
    return documents