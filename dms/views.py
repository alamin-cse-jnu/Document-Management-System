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
    }
    
    return render(request, 'dms/document_detail.html', context)

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
    
    # Serve the file
    response = HttpResponse(document.file, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{document.file.name.split("/")[-1]}"'
    return response

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

@role_required(['AD'])  # Only admin
def team_delete(request, pk):
    team = get_object_or_404(Team, pk=pk)
    
    if request.method == 'POST':
        team_name = team.name
        team.delete()
        messages.success(request, f"Team '{team_name}' deleted successfully.")
    
    return redirect('dms:team_management')

@role_required(['AD'])  # Only admin
def user_list(request):
    users = User.objects.all().order_by('username')
    
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
            
            # Set user role
            profile = user.profile
            profile.role = form.cleaned_data['role']
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
            
            # Set user role
            profile = user.profile
            profile.role = form.cleaned_data['role']
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
        }
        form = UserRegistrationForm(instance=user, initial=initial_data)
        # Make password fields not required for update
        form.fields['password'].required = False
        form.fields['confirm_password'].required = False
    
    return render(request, 'dms/user_form.html', {'form': form, 'user_obj': user})

@role_required(['AD'])  # Only admin
def user_delete(request, pk):
    user = get_object_or_404(User, pk=pk)
    
    # Prevent deleting yourself
    if user == request.user:
        messages.error(request, "You cannot delete your own account.")
        return redirect('dms:user_list')
    
    if request.method == 'POST':
        username = user.username
        user.delete()
        messages.success(request, f"User '{username}' deleted successfully.")
    
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