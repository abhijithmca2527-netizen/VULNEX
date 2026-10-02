from django.contrib import admin
from .models import ScanResult, SandboxThreat

admin.site.register(ScanResult)
admin.site.register(SandboxThreat)