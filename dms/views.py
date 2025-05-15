# dms/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.db.models import Q
from django.core.paginator import Paginator
from django.contrib.auth.models import User
from django.contrib.auth import logout
from django.contrib.auth.views import LoginView
from .models import Document, Team, Category, Comment, AuditLog, DocumentPermission, UserProfile
from .forms import DocumentForm, CommentForm, DocumentShareForm, UserRegistrationForm
from .decorators import role_required
from django.db.models import Count
import os
from django.conf import settings

def create_audit_log(user, action_type, target_object, details=''):
    """Helper function to create audit logs"""
    AuditLog.objects.create(
        user=user,
        action_type=action_type,
        target_object=target_object,
        details=details
    )

@login_required
def dashboard(request):
    user = request.user
    user_teams = user.teams.all()
    
    # Get recent documents the user has access to
    recent_documents = Document.objects.filter(
        Q(owner=user) |  # Documents owned by user
        Q(visibility=Document.VISIBILITY_PUBLIC) |  # Public documents
        (Q(visibility=Document.VISIBILITY_TEAM) &   # Team documents where user is a member
         Q(owner__teams__in=user_teams)) |
        Q(permissions__user=user) |  # Direct permissions
        Q(permissions__team__in=user_teams)  # Team permissions
    ).distinct().order_by('-upload_date')[:5]
    
    # Get recent comments
    recent_comments = Comment.objects.filter(
        Q(user=user) |  # Comments by user
        Q(document__owner=user)  # Comments on user's documents
    ).order_by('-created_at')[:5]
    
    # Get user's teams
    teams = user.teams.all()
    
    # Get recent audit logs for admin
    recent_activities = None
    if user.profile.role == UserProfile.ROLE_ADMIN:
        recent_activities = AuditLog.objects.all().order_by('-timestamp')[:10]
    
    context = {
        'recent_documents': recent_documents,
        'recent_comments': recent_comments,
        'teams': teams,
        'recent_activities': recent_activities,
    }
    
    return render(request, 'dms/dashboard.html', context)


@login_required
def document_list(request):
    user = request.user
    user_teams = user.teams.all()
    
    # Get documents the user has access to
    documents = Document.objects.filter(
        Q(owner=user) |  # Documents owned by user
        Q(visibility=Document.VISIBILITY_PUBLIC) |  # Public documents
        (Q(visibility=Document.VISIBILITY_TEAM) &   # Team documents where user is a member
         Q(owner__teams__in=user_teams)) |
        Q(permissions__user=user) |  # Direct permissions
        Q(permissions__team__in=user_teams)  # Team permissions
    ).distinct()
    
    # Handle search and filtering
    category = request.GET.get('category')
    tag = request.GET.get('tag')
    query = request.GET.get('q')
    
    if category:
        documents = documents.filter(categories__id=category)
    if tag:
        documents = documents.filter(tags__icontains=tag)
    if query:
        documents = documents.filter(
            Q(title__icontains=query) |
            Q(description__icontains=query)
        )
    
    # Pagination
    paginator = Paginator(documents.order_by('-upload_date'), 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'categories': Category.objects.all(),
    }
    
    return render(request, 'dms/document_list.html', context)

@login_required
def document_create(request):
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            document = form.save(commit=False)
            document.owner = request.user
            document.save()
            
            # Save categories
            form.save_m2m()
            
            create_audit_log(request.user, AuditLog.ACTION_UPLOAD, f"Document: {document.id}")
            messages.success(request, "Document uploaded successfully!")
            return redirect('dms:document_detail', pk=document.id)
    else:
        form = DocumentForm()
    
    return render(request, 'dms/document_form.html', {'form': form})

@login_required
def document_detail(request, pk):
    document = get_object_or_404(Document, pk=pk)
    user = request.user
    user_teams = user.teams.all()
    
    # Check if user has access
    has_access = (
        document.owner == user or
        document.visibility == Document.VISIBILITY_PUBLIC or
        (document.visibility == Document.VISIBILITY_TEAM and 
         document.owner.teams.filter(id__in=user_teams.values_list('id', flat=True)).exists()) or
        document.permissions.filter(Q(user=user) | Q(team__in=user_teams)).exists()
    )
    
    if not has_access:
        messages.error(request, "You don't have permission to access this document.")
        return redirect('dms:document_list')
    
    # Check if file exists
    file_exists = document.file and os.path.exists(document.file.path)
    
    # Log view event
    create_audit_log(user, AuditLog.ACTION_VIEW, f"Document: {document.id}")
    
    # Handle comment form
    if request.method == 'POST':
        comment_form = CommentForm(request.POST)
        if comment_form.is_valid():
            comment = comment_form.save(commit=False)
            comment.document = document
            comment.user = user
            parent_id = request.POST.get('parent_comment')
            if parent_id:
                comment.parent_comment = get_object_or_404(Comment, id=parent_id)
            comment.save()
            create_audit_log(user, 'CM', f"Comment on Document: {document.id}")
            return redirect('dms:document_detail', pk=pk)
    else:
        comment_form = CommentForm()
    
    # Get document permissions
    user_permission = DocumentPermission.objects.filter(
        document=document, 
        user=user
    ).first()
    
    team_permissions = DocumentPermission.objects.filter(
        document=document,
        team__in=user_teams
    )
    
    # Determine highest permission level
    permission_level = None
    if document.owner == user:
        permission_level = 'owner'
    elif user_permission:
        permission_level = user_permission.permission_type
    elif team_permissions.exists():
        # Get highest permission from team permissions
        if team_permissions.filter(permission_type=DocumentPermission.PERMISSION_SHARE).exists():
            permission_level = DocumentPermission.PERMISSION_SHARE
        elif team_permissions.filter(permission_type=DocumentPermission.PERMISSION_WRITE).exists():
            permission_level = DocumentPermission.PERMISSION_WRITE
        elif team_permissions.filter(permission_type=DocumentPermission.PERMISSION_COMMENT).exists():
            permission_level = DocumentPermission.PERMISSION_COMMENT
        else:
            permission_level = DocumentPermission.PERMISSION_READ
    
    context = {
        'document': document,
        'comments': document.comments.filter(parent_comment__isnull=True),
        'comment_form': comment_form,
        'permission_level': permission_level,
        'can_edit': permission_level in ['owner', DocumentPermission.PERMISSION_WRITE],
        'can_comment': permission_level in ['owner', DocumentPermission.PERMISSION_WRITE, 
                                          DocumentPermission.PERMISSION_COMMENT],
        'can_share': permission_level in ['owner', DocumentPermission.PERMISSION_SHARE],
        'file_exists': file_exists,
    }
    
    return render(request, 'dms/document_detail.html', context)

@login_required
def document_update(request, pk):
    document = get_object_or_404(Document, pk=pk)
    
    # Check if user has permission to edit
    if document.owner != request.user and not DocumentPermission.objects.filter(
        document=document,
        user=request.user,
        permission_type=DocumentPermission.PERMISSION_WRITE
    ).exists() and not DocumentPermission.objects.filter(
        document=document,
        team__in=request.user.teams.all(),
        permission_type=DocumentPermission.PERMISSION_WRITE
    ).exists():
        messages.error(request, "You don't have permission to edit this document.")
        return redirect('dms:document_detail', pk=pk)
    
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES, instance=document)
        if form.is_valid():
            # If new file uploaded, increment version
            if 'file' in request.FILES:
                document.version += 1
            
            form.save()
            create_audit_log(request.user, AuditLog.ACTION_EDIT, f"Document: {document.id}")
            messages.success(request, "Document updated successfully!")
            return redirect('dms:document_detail', pk=document.id)
    else:
        form = DocumentForm(instance=document)
    
    return render(request, 'dms/document_form.html', {'form': form, 'document': document})

@login_required
def document_share(request, pk):
    document = get_object_or_404(Document, pk=pk)
    
    # Check if user has permission to share
    if document.owner != request.user and not DocumentPermission.objects.filter(
        document=document,
        user=request.user,
        permission_type=DocumentPermission.PERMISSION_SHARE
    ).exists() and not DocumentPermission.objects.filter(
        document=document,
        team__in=request.user.teams.all(),
        permission_type=DocumentPermission.PERMISSION_SHARE
    ).exists():
        messages.error(request, "You don't have permission to share this document.")
        return redirect('dms:document_detail', pk=pk)
    
    if request.method == 'POST':
        form = DocumentShareForm(request.POST)
        if form.is_valid():
            teams = form.cleaned_data['teams']
            users = form.cleaned_data['users']
            permission_type = form.cleaned_data['permission']
            
            # Create permissions for teams
            for team in teams:
                DocumentPermission.objects.update_or_create(
                    document=document,
                    team=team,
                    defaults={'permission_type': permission_type}
                )
            
            # Create permissions for users
            for user in users:
                DocumentPermission.objects.update_or_create(
                    document=document,
                    user=user,
                    defaults={'permission_type': permission_type}
                )
            
            create_audit_log(
                request.user, 
                AuditLog.ACTION_SHARE, 
                f"Document: {document.id}",
                f"Shared with teams: {', '.join(t.name for t in teams)} and users: {', '.join(u.username for u in users)}"
            )
            
            messages.success(request, "Document shared successfully!")
            return redirect('dms:document_detail', pk=document.id)
    else:
        form = DocumentShareForm()
    
    context = {
        'form': form,
        'document': document,
    }
    
    return render(request, 'dms/document_share.html', context)

@login_required
def document_download(request, pk):
    document = get_object_or_404(Document, pk=pk)
    user = request.user
    user_teams = user.teams.all()
    
    # Check if user has access
    has_access = (
        document.owner == user or
        document.visibility == Document.VISIBILITY_PUBLIC or
        (document.visibility == Document.VISIBILITY_TEAM and 
         document.owner.teams.filter(id__in=user_teams.values_list('id', flat=True)).exists()) or
        document.permissions.filter(Q(user=user) | Q(team__in=user_teams)).exists()
    )
    
    if not has_access:
        messages.error(request, "You don't have permission to download this document.")
        return redirect('dms:document_list')
    
    # Log download event
    create_audit_log(user, AuditLog.ACTION_DOWNLOAD, f"Document: {document.id}")
    
    # Check if the file exists in the file system
    file_path = document.file.path if document.file else None
    
    if not file_path or not os.path.exists(file_path):
        messages.error(request, f"The file for document '{document.title}' is missing from the server. Please contact an administrator.")
        return redirect('dms:document_detail', pk=document.id)
    
    # Serve the file
    try:
        with open(file_path, 'rb') as file:
            response = HttpResponse(file.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
    except Exception as e:
        messages.error(request, f"Error downloading file: {str(e)}")
        return redirect('dms:document_detail', pk=document.id)

@login_required
@role_required(['AD'])  # Only admin
def document_delete(request, pk):
    """Delete document with confirmation"""
    document = get_object_or_404(Document, pk=pk)
    
    if request.method == 'POST':
        document_title = document.title
        
        # Log delete event before deleting the document
        create_audit_log(request.user, AuditLog.ACTION_DELETE, f"Document: {document.id} - {document_title}")
        
        try:
            # Delete document file from storage
            if document.file:
                if os.path.isfile(document.file.path):
                    os.remove(document.file.path)
            
            # Delete document record
            document.delete()
            messages.success(request, f"Document '{document_title}' deleted successfully.")
        except Exception as e:
            messages.error(request, f"Error deleting document: {str(e)}")
    
    return redirect('dms:document_list')

@login_required
@role_required(['AD'])  # Only admin
def sync_files(request):
    """Sync files in the database with the file system"""
    if request.method == 'POST':
        # Get all documents
        documents = Document.objects.all()
        missing_files = []
        orphaned_files = []
        
        # Check for missing files in the database
        for document in documents:
            if document.file and not os.path.exists(document.file.path):
                missing_files.append(document)
        
        # Check for orphaned files in the file system
        uploads_dir = os.path.join(settings.MEDIA_ROOT, 'uploads/documents')
        if os.path.exists(uploads_dir):
            db_files = set([os.path.basename(doc.file.name) for doc in documents if doc.file])
            
            for filename in os.listdir(uploads_dir):
                if filename not in db_files and os.path.isfile(os.path.join(uploads_dir, filename)):
                    orphaned_files.append(filename)
        
        context = {
            'missing_files': missing_files,
            'orphaned_files': orphaned_files,
        }
        
        return render(request, 'dms/sync_files_result.html', context)
    
    return render(request, 'dms/sync_files.html')

@login_required
@role_required(['AD'])  # Only admin
def fix_missing_file(request, pk):
    """Allow admin to upload a replacement file for a document with a missing file"""
    document = get_object_or_404(Document, pk=pk)
    
    if request.method == 'POST':
        if 'file' in request.FILES:
            # Delete old file record if it exists but the file is missing
            if document.file and not os.path.exists(document.file.path):
                # Just update the file field, don't try to delete the non-existent file
                document.file = request.FILES['file']
                document.save()
                messages.success(request, f"File for document '{document.title}' has been replaced.")
                return redirect('dms:document_detail', pk=pk)
            else:
                messages.error(request, "This document's file exists or is not set. Use the regular edit function.")
        else:
            messages.error(request, "No file was uploaded.")
    
    context = {
        'document': document,
    }
    
    return render(request, 'dms/fix_missing_file.html', context)

@role_required(['AD', 'TL'])  # Admin or team leader
def team_management(request):
    user_profile = request.user.profile
    
    if user_profile.role == UserProfile.ROLE_ADMIN:
        teams = Team.objects.all()
    else:
        # Team leaders can only manage their own teams
        teams = Team.objects.filter(members=request.user)
    
    # Get all users for team member selection
    users = User.objects.all().order_by('username')
    
    context = {
        'teams': teams,
        'users': users
    }
    
    return render(request, 'dms/team_management.html', context)


@role_required(['AD', 'TL'])  # Admin or team leader
def team_create(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        member_ids = request.POST.getlist('members')
        
        if not name:
            messages.error(request, "Team name is required.")
            return redirect('dms:team_management')
        
        team = Team.objects.create(name=name)
        
        # Add current user as a member
        team.members.add(request.user)
        
        # Add other members
        if member_ids:
            members = User.objects.filter(id__in=member_ids)
            team.members.add(*members)
        
        messages.success(request, f"Team '{name}' created successfully.")
    
    return redirect('dms:team_management')

@role_required(['AD', 'TL'])  # Admin or team leader
def team_update(request, pk):
    team = get_object_or_404(Team, pk=pk)
    
    # Team leaders can only edit their own teams
    user_profile = request.user.profile
    if user_profile.role != UserProfile.ROLE_ADMIN and (user_profile.role != UserProfile.ROLE_TEAM_LEADER or request.user not in team.members.all()):
        messages.error(request, "You don't have permission to edit this team.")
        return redirect('dms:team_management')
    
    if request.method == 'POST':
        name = request.POST.get('name')
        member_ids = request.POST.getlist('members')
        
        if not name:
            messages.error(request, "Team name is required.")
            return redirect('dms:team_management')
        
        team.name = name
        team.save()
        
        # Update members
        current_members = set(team.members.values_list('id', flat=True))
        new_members = set(map(int, member_ids)) if member_ids else set()
        
        # Ensure the current user (team leader) remains a member
        new_members.add(request.user.id)
        
        # Add new members
        members_to_add = new_members - current_members
        if members_to_add:
            members = User.objects.filter(id__in=members_to_add)
            team.members.add(*members)
        
        # Remove members
        members_to_remove = current_members - new_members
        if members_to_remove:
            members = User.objects.filter(id__in=members_to_remove)
            team.members.remove(*members)
        
        messages.success(request, f"Team '{name}' updated successfully.")
    
    return redirect('dms:team_management')

@login_required
def team_detail(request, pk):
    """View team details and member list"""
    team = get_object_or_404(Team, pk=pk)
    user = request.user
    
    # Check if user is a member of the team or an admin
    is_member = user in team.members.all()
    is_admin = user.profile.role == UserProfile.ROLE_ADMIN
    is_team_leader = user.profile.role == UserProfile.ROLE_TEAM_LEADER and is_member
    
    if not (is_member or is_admin):
        messages.error(request, "You don't have permission to view this team's details.")
        return redirect('dms:dashboard')
    
    # Get team members with their profile information
    team_members = team.members.all().select_related('profile')
    
    # Get documents shared with this team
    team_documents = Document.objects.filter(
        Q(permissions__team=team) |  # Documents explicitly shared with the team
        Q(owner__in=team_members, visibility=Document.VISIBILITY_TEAM)  # Team-visible documents owned by team members
    ).distinct().order_by('-upload_date')
    
    context = {
        'team': team,
        'team_members': team_members,
        'team_documents': team_documents,
        'is_team_leader': is_team_leader,
        'is_admin': is_admin,
    }
    
    return render(request, 'dms/team_detail.html', context)

@login_required
@role_required(['AD'])  # Only admin
def team_delete(request, pk):
    team = get_object_or_404(Team, pk=pk)
    
    if request.method == 'POST':
        team_name = team.name
        
        try:
            # Log the action before deleting
            create_audit_log(request.user, 'DL', f"Team: {team.id} - {team_name}")
            
            # Delete the team
            team.delete()
            messages.success(request, f"Team '{team_name}' deleted successfully.")
        except Exception as e:
            messages.error(request, f"Error deleting team: {str(e)}")
    
    return redirect('dms:team_management')

@role_required(['AD'])  # Only admin
def user_list(request):
    """Display all users with search functionality"""
    users = User.objects.all().order_by('username')
    
    # Handle search
    search_query = request.GET.get('q')
    if search_query:
        users = users.filter(
            Q(username__icontains=search_query) |
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(email__icontains=search_query)
        )
    
    context = {
        'users': users
    }
    
    return render(request, 'dms/user_list.html', context)

@role_required(['AD'])  # Only admin
def user_create(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            # Create user
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()
            
            # Set user role and additional profile fields
            profile = user.profile
            profile.role = form.cleaned_data['role']
            profile.phone_number = form.cleaned_data.get('phone_number', '')
            profile.designation = form.cleaned_data.get('designation', '')
            profile.save()
            
            # Add user to teams
            teams = form.cleaned_data.get('teams')
            if teams:
                for team in teams:
                    team.members.add(user)
            
            messages.success(request, f"User '{user.username}' created successfully.")
            return redirect('dms:user_list')
    else:
        form = UserRegistrationForm()
    
    return render(request, 'dms/user_form.html', {'form': form})

@role_required(['AD'])  # Only admin
def user_update(request, pk):
    user = get_object_or_404(User, pk=pk)
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST, instance=user)
        if form.is_valid():
            # Update user
            user = form.save(commit=False)
            
            # Only set password if it was changed
            if form.cleaned_data['password']:
                user.set_password(form.cleaned_data['password'])
            
            user.save()
            
            # Set user role and additional profile fields
            profile = user.profile
            profile.role = form.cleaned_data['role']
            profile.phone_number = form.cleaned_data.get('phone_number', '')
            profile.designation = form.cleaned_data.get('designation', '')
            profile.save()
            
            # Update teams
            current_teams = user.teams.all()
            new_teams = form.cleaned_data.get('teams', [])
            
            # Remove from teams not in selection
            for team in current_teams:
                if team not in new_teams:
                    team.members.remove(user)
            
            # Add to new teams
            for team in new_teams:
                if team not in current_teams:
                    team.members.add(user)
            
            messages.success(request, f"User '{user.username}' updated successfully.")
            return redirect('dms:user_list')
    else:
        # Pre-populate the form
        initial_data = {
            'role': user.profile.role,
            'teams': user.teams.all(),
            'phone_number': user.profile.phone_number,
            'designation': user.profile.designation,
        }
        form = UserRegistrationForm(instance=user, initial=initial_data)
        # Make password fields not required for update
        form.fields['password'].required = False
        form.fields['confirm_password'].required = False
    
    return render(request, 'dms/user_form.html', {'form': form, 'user_obj': user})

@role_required(['AD'])  # Only admin
def user_delete(request, pk):
    """Delete user with confirmation"""
    user = get_object_or_404(User, pk=pk)
    
    # Prevent deleting yourself
    if user == request.user:
        messages.error(request, "You cannot delete your own account.")
        return redirect('dms:user_list')
    
    if request.method == 'POST':
        username = user.username
        try:
            # Delete user
            user.delete()
            messages.success(request, f"User '{username}' deleted successfully.")
        except Exception as e:
            messages.error(request, f"Error deleting user: {str(e)}")
    
    return redirect('dms:user_list')

# Helper function to fix missing profiles
@role_required(['AD'])  # Only admin
def fix_user_profiles(request):
    """Fix missing user profiles"""
    users_without_profiles = []
    
    for current_user in User.objects.all():
        try:
            # Check if user has a profile
            profile = current_user.profile
        except UserProfile.DoesNotExist:
            # Create profile if it doesn't exist
            profile = UserProfile.objects.create(user=current_user)
            users_without_profiles.append(current_user.username)
    
    if users_without_profiles:
        messages.success(
            request, 
            f"Fixed profiles for the following users: {', '.join(users_without_profiles)}"
        )
    else:
        messages.info(request, "All users already have profiles.")
    
    return redirect('dms:user_list')



def logout_view(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('login')

# Custom login view to add a success message
class CustomLoginView(LoginView):
    def form_valid(self, form):
        messages.success(self.request, f"Welcome, {form.get_user().username}!")
        return super().form_valid(form)

@login_required
@role_required(['AD'])  # Only admin
def admin_reports(request):
    """Admin dashboard with reports and statistics"""
    # User statistics
    total_users = User.objects.count()
    all_users = User.objects.all().select_related('profile')
    
    # Team statistics
    total_teams = Team.objects.count()
    teams_with_members = Team.objects.annotate(member_count=Count('members')).order_by('-member_count')
    
    # Document statistics
    total_documents = Document.objects.count()
    recent_documents = Document.objects.order_by('-upload_date')[:10]
    all_documents = Document.objects.all().select_related('owner').prefetch_related('categories', 'permissions__team')
    
    # Documents by category for stats
    categories = Category.objects.all()
    documents_by_category = []
    
    for category in categories:
        doc_count = category.documents.count()
        if doc_count > 0:
            documents_by_category.append({
                'name': category.name,
                'count': doc_count,
                'percentage': (doc_count / total_documents * 100) if total_documents > 0 else 0
            })
    
    # Most active users
    most_active_users = AuditLog.objects.values('user__username').annotate(
        action_count=Count('id')
    ).order_by('-action_count')[:5]
    
    context = {
        'total_users': total_users,
        'all_users': all_users,
        'total_teams': total_teams,
        'teams_with_members': teams_with_members,
        'total_documents': total_documents,
        'all_documents': all_documents,
        'recent_documents': recent_documents,
        'documents_by_category': documents_by_category,
        'most_active_users': most_active_users,
    }
    
    return render(request, 'dms/admin_reports.html', context)

@login_required
@role_required(['AD'])  # Only admin
def export_report(request, report_type):
    """Export reports in different formats"""
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{report_type}_report.csv"'
    
    writer = csv.writer(response)
    
    if report_type == 'users':
        # Export user data
        writer.writerow(['Username', 'Full Name', 'Email', 'Role', 'Teams'])
        users = User.objects.all()
        
        for user in users:
            try:
                role = user.profile.get_role_display()
            except:
                role = 'N/A'
                
            teams = ', '.join([team.name for team in user.teams.all()])
            writer.writerow([
                user.username,
                user.get_full_name(),
                user.email,
                role,
                teams
            ])
            
    elif report_type == 'documents':
        # Export document data
        writer.writerow(['Title', 'Owner', 'Categories', 'Visibility', 'Upload Date'])
        documents = Document.objects.all()
        
        for doc in documents:
            categories = ', '.join([cat.name for cat in doc.categories.all()])
            writer.writerow([
                doc.title,
                doc.owner.username,
                categories,
                doc.get_visibility_display(),
                doc.upload_date.strftime('%Y-%m-%d')
            ])
    
    return response

@login_required
@role_required(['AD'])  # Only admin
def export_report(request, report_type):
    """Export reports in different formats"""
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{report_type}_report.csv"'
    
    writer = csv.writer(response)
    
    if report_type == 'users':
        # Export user data
        writer.writerow(['ID', 'Username', 'Full Name', 'Designation', 'Phone', 'Email', 'Role', 'Teams'])
        users = User.objects.all().select_related('profile')
        
        for user in users:
            try:
                role = user.profile.get_role_display()
                designation = user.profile.designation or 'N/A'
                phone = user.profile.phone_number or 'N/A'
            except:
                role = 'N/A'
                designation = 'N/A'
                phone = 'N/A'
                
            teams = ', '.join([team.name for team in user.teams.all()])
            writer.writerow([
                user.id,
                user.username,
                user.get_full_name(),
                designation,
                phone,
                user.email,
                role,
                teams
            ])
            
    elif report_type == 'teams':
        # Export team data
        writer.writerow(['Team Name', 'Member Count', 'Members'])
        teams = Team.objects.all().prefetch_related('members')
        
        for team in teams:
            members = ', '.join([member.username for member in team.members.all()])
            writer.writerow([
                team.name,
                team.members.count(),
                members
            ])
            
    elif report_type == 'documents':
        # Export document data
        writer.writerow(['Title', 'Version', 'Visibility', 'Categories', 'Uploaded By', 'Date', 'Shared With'])
        documents = Document.objects.all().select_related('owner').prefetch_related('categories', 'permissions__team')
        
        for doc in documents:
            categories = ', '.join([cat.name for cat in doc.categories.all()])
            shared_with = ', '.join([perm.team.name for perm in doc.permissions.filter(team__isnull=False)])
            
            writer.writerow([
                doc.title,
                doc.version,
                doc.get_visibility_display(),
                categories,
                doc.owner.username,
                doc.upload_date.strftime('%Y-%m-%d'),
                shared_with
            ])
    
    return response