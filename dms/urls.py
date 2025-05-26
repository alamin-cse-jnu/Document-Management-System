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
    path('document/<int:pk>/delete/', views.document_delete, name='document_delete'),
    path('admin/sync-files/', views.sync_files, name='sync_files'),
    path('admin/fix-missing-file/<int:pk>/', views.fix_missing_file, name='fix_missing_file'),
    
    # User management
    path('users/', views.user_list, name='user_list'),
    path('users/create/', views.user_create, name='user_create'),
    path('users/<int:pk>/update/', views.user_update, name='user_update'),
    path('users/<int:pk>/delete/', views.user_delete, name='user_delete'),
    path('users/fix-profiles/', views.fix_user_profiles, name='fix_user_profiles'),
    path('reports/', views.admin_reports, name='admin_reports'),
    path('reports/export/<str:report_type>/', views.export_report, name='export_report'),
    
    # Team management
    path('teams/', views.team_management, name='team_management'),
    path('teams/create/', views.team_create, name='team_create'),
    path('teams/<int:pk>/update/', views.team_update, name='team_update'),
    path('teams/<int:pk>/delete/', views.team_delete, name='team_delete'),
    path('teams/<int:pk>/', views.team_detail, name='team_detail'),

    #Category Management
    path('categories/', views.category_list, name='category_list'),
    path('categories/create/', views.category_create, name='category_create'),
    path('categories/<int:pk>/update/', views.category_update, name='category_update'),
    path('categories/<int:pk>/delete/', views.category_delete, name='category_delete'),

    # Folder management URLs
    path('folders/', views.folder_browser, name='folder_browser'),
    path('folders/category/<int:category_id>/', views.folder_browser, name='folder_browser_category'),
    path('folder/<int:folder_id>/', views.folder_detail, name='folder_detail'),
    path('folder/create/', views.folder_create, name='folder_create'),
    path('folder/create/category/<int:category_id>/', views.folder_create, name='folder_create_in_category'),
    path('folder/create/parent/<int:parent_folder_id>/', views.folder_create, name='folder_create_in_folder'),
    path('folder/<int:folder_id>/update/', views.folder_update, name='folder_update'),
    path('folder/<int:folder_id>/delete/', views.folder_delete, name='folder_delete'),
    path('folder/<int:folder_id>/move/', views.folder_move, name='folder_move'),
    
    # AJAX endpoints
    path('api/folder-tree/<int:category_id>/', views.get_folder_tree_json, name='folder_tree_json'),

    # Document draft management
    path('document/<int:pk>/publish/', views.document_publish, name='document_publish'),
    path('document/<int:pk>/unpublish/', views.document_unpublish, name='document_unpublish'),
    path('document/<int:pk>/move/', views.document_move, name='document_move'),
    path('my-drafts/', views.my_drafts, name='my_drafts'),
]