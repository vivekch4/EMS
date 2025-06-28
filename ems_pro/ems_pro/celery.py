import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ems_pro.settings')
app = Celery('ems_pro')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

# Optional: Define beat schedule here instead of settings.py
app.conf.beat_schedule = {
    'read-modbus-every-second': {
        'task': 'ems_app.tasks.read_modbus_data',  # Replace 'your_app' with your app name
        'schedule': 60.0,  # Run every second
    },
}

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')