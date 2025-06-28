from django.urls import re_path
from . import consumers



websocket_urlpatterns = [
    re_path(r'ws/readings/$', consumers.MachineReadingConsumer.as_asgi()),
    re_path(r'ws/notifications/$', consumers.MachineReadingConsumer.as_asgi()),  # Add notifications route
]