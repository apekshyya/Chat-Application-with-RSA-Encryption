from django.apps import AppConfig


class RsaAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'rsa_app'    
    def ready(self):
        import rsa_app.signals