import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import ems_app.routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ems_pro.settings')

application = ProtocolTypeRouter({
    'http': get_asgi_application(),
    'websocket': AuthMiddlewareStack(
        URLRouter(
            ems_app.routing.websocket_urlpatterns
        )
    ),
})