# dmsEparliament/urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic.base import RedirectView
from dms.views import logout_view, CustomLoginView
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('', RedirectView.as_view(url='/accounts/login/', permanent=False)),
    path('admin/', admin.site.urls),
    path('dms/', include('dms.urls')),
    path('accounts/login/', CustomLoginView.as_view(template_name='registration/login.html'), name='login'),
    path('accounts/logout/', logout_view, name='logout'),
    path('accounts/', include('django.contrib.auth.urls')),
]


if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)