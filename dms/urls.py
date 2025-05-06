# dms/urls.py
from django.urls import path
from . import views

app_name = 'dms'

urlpatterns = [
    # Dashboard
    path('', views.dashboard, name='dashboard'),
    
    # Document management
    path('documents/', views.document_list, name='document_list'),
    path('document/<int:pk>/', views.document_detail, name='document_detail'),
    path('document/create/', views.document_create, name='document_create'),
    path('document/<int:pk>/update/', views.document_update, name='document_update'),
    path('document/<int:pk>/share/', views.document_share, name='document_share'),
    path('document/<int:pk>/download/', views.document_download, name='document_download'),
    
    # User management
    path('users/', views.user_list, name='user_list'),
    path('users/create/', views.user_create, name='user_create'),
    path('users/<int:pk>/update/', views.user_update, name='user_update'),
    path('users/<int:pk>/delete/', views.user_delete, name='user_delete'),
    path('users/fix-profiles/', views.fix_user_profiles, name='fix_user_profiles'),
    
    # Team management
    path('teams/', views.team_management, name='team_management'),
    path('teams/create/', views.team_create, name='team_create'),
    path('teams/<int:pk>/update/', views.team_update, name='team_update'),
    path('teams/<int:pk>/delete/', views.team_delete, name='team_delete'),
]