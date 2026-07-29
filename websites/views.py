from django.shortcuts import render, redirect
from django.contrib import messages
from .tasks import run_vulnex_scan

# --- ADD THIS MISSING FUNCTION ---
def dashboard_view(request):
    # This tells Django to load your HTML file when someone visits the dashboard URL
    return render(request, 'dashboard/dashboard.html')
# ---------------------------------

def start_scan_view(request, website_id):
    if request.method == "POST":
        # Grab the URL the user typed into your HTML input box
        website_url = request.POST.get('target_url')
        scan_id = 101 # Still hardcoded for Phase 1 testing
        
        # Trigger Celery in the background!
        run_vulnex_scan.delay(website_url, scan_id)
        
        # Add a success message to display on the frontend
        messages.success(request, f"Scan initiated for {website_url}! The AI is working in the background.")
        
    # Redirect back to the dashboard_view we just created above
    return redirect('dashboard')