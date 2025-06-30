from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

# router = DefaultRouter()

# router.register(r'machines', MachineViewSet)
# router.register(r'readings', EnergyReadingViewSet)

urlpatterns = [
    path('users/', UserListCreateView.as_view(), name='user_list_create'),
    path('create-user/', create_user_view, name='create_user'),
    path('user-page/', users_page_view, name='user_page'),
    path('users/<int:id>/', UserDetailView.as_view(), name='user_detail'),
    
    
    path('dashboard/', dashboard, name='dashboard'),
    path('machines/<int:pk>/', MachineDetailView.as_view(), name='machine-detail'),
    path('config/', config_page, name='config'),
    path('report/', report_page, name='report'),
    path('login/', LoginView.as_view(), name='login'),
    path('', login_page, name='login_page'),
    path('logout/', LogoutView.as_view(), name='logout'),

    path('connect/', ConnectView.as_view(), name='connect'),
    path('machines/', MachineListCreateView.as_view(), name='machine-list-create'),
    
    path('machine-readings/report/', MachineReadingReportView.as_view(), name='machine-reading-report'),
    path('machine-readings/export/', MachineReadingExportView.as_view(), name='machine-reading-export'),
   
    path('connection/', connection_page, name='connection_page'),
    # Template Endpoint
    path('config/', config_page, name='config_page'),
    path('create_machine/', create_config, name='create_machine'),  
    
    path('Analytics_page/', Analytics_page, name='Analytics_page'),
    path('readings/', MachineReadingListView.as_view(), name='readings-list'),# 
     
     
    path('alarm_page/', alarm_page, name='alarm_page'),
    path('create_alarm_page/', create_alarm_page, name='create_alarm_page'),
    path('thresholds/', ThresholdListCreateView.as_view(), name='threshold-list-create'),
    path('thresholds/<int:pk>/', ThresholdDetailView.as_view(), name='threshold-detail'),
    
     path('kwh-summary/', MachineKwhSummaryView.as_view(), name='machine-kwh-summary'),
     path('tariff_page/', tariff_page, name='tariff_page'),
     path('tariff/set/', TariffSetView.as_view(), name='tariff-set'),
    path('tariff/report/', TariffReportView.as_view(), name='tariff-report'),
    path('tariff/export/', TariffExportView.as_view(), name='tariff-export'),
    path('send_alert/', SendAlertView.as_view(), name='send_alert'),
]