# dms/decorators.py

from django.shortcuts import redirect
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from functools import wraps

def role_required(allowed_roles):
    """
    Decorator for views that checks whether a user has a specific role,
    redirecting to the login page if necessary.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('login')
            
            # Make sure we're accessing the role correctly
            try:
                user_role = request.user.profile.role
                if user_role in allowed_roles:
                    return view_func(request, *args, **kwargs)
                else:
                    messages.error(request, "You don't have permission to access this page.")
                    return redirect('dms:document_list')
            except AttributeError:
                # If the user doesn't have a profile for some reason, redirect to login
                messages.error(request, "Your user account is not properly configured. Please contact an administrator.")
                return redirect('dms:document_list')
                
        return _wrapped_view
    return decorator