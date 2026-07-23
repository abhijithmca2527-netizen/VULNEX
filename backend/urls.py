from django.contrib import admin
from django.shortcuts import render
from django.urls import path, include

def home(request):
    return render(request, "home/index.html")

urlpatterns = [
    path('', home, name='home'),
    path('admin/', admin.site.urls),
    path('', include('users.urls')),
]