from django.shortcuts import render, redirect
from .tasks import run_vulnex_scan

def dashboard_view(request):
    """Renders the main dashboard template."""
    return render(request, 'dashboard.html')

def start_scan_view(request):
    """Handles URL submission and sends job to Celery."""
    if request.method == "POST":
        target_url = request.POST.get("target_url")
        if target_url:
            run_vulnex_scan.delay(target_url)
        return redirect('dashboard')
    return redirect('dashboard')