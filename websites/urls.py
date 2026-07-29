from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard_view, name='dashboard'),
    path('scan/start/', views.start_scan_view, name='start_scan'),
]