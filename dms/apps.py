# dms/apps.py

from django.apps import AppConfig

class DmsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'dms'
    
    def ready(self):
        import dms.signals