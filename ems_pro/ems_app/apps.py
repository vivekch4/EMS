from django.apps import AppConfig


class EmsAppConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "ems_app"
    def ready(self):
        import ems_app.signals 
