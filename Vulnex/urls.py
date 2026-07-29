from django.contrib import admin
from django.shortcuts import render
from django.urls import path, include
from websites import views

def home(request):
    return render(request, "home/index.html")

urlpatterns = [
    path('', home, name='home'),
    path('admin/', admin.site.urls),
    path('', include('users.urls')),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('scan/<int:website_id>/', views.start_scan_view, name='start_scan'),
]