from celery import shared_task
import time

@shared_task
def run_vulnex_scan(website_url, scan_id):
    """
    Background task to scan the website without freezing the UI.
    """
    print(f"[VULNEX] Starting background scan for: {website_url}")
    
    # Simulate a 5-second scan for Phase 1 testing
    time.sleep(5) 
    
    print(f"[VULNEX] Scan complete for Scan ID: {scan_id}!")
    return True 