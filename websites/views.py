from django.shortcuts import render, redirect
from django.http import JsonResponse
from celery.result import AsyncResult
from .tasks import run_vulnex_scan
from .utils import VULNERABILITY_DICT

def dashboard_view(request):
    """Renders the main dashboard template."""
    return render(request, 'dashboard.html')

def start_scan_view(request):
    """Handles URL submission, sends job to Celery, and loads the spinner."""
    if request.method == "POST":
        target_url = request.POST.get("target_url")
        if target_url:
            # Trigger the 30-second background task
            task = run_vulnex_scan.delay(target_url)
            
            # Render the loading page and pass the Task ID so JavaScript can track it
            return render(request, 'websites/loading.html', {
                'task_id': task.id, 
                'target_url': target_url
            })
    return redirect('dashboard')

def check_scan_status(request, task_id):
    """
    API endpoint that the loading screen pings every 3 seconds 
    to check if Celery has finished the task.
    """
    task_result = AsyncResult(task_id)
    
    if task_result.state == 'SUCCESS':
        return JsonResponse({'status': 'SUCCESS'})
    elif task_result.state == 'FAILURE':
        return JsonResponse({'status': 'FAILURE'})
    else:
        return JsonResponse({'status': 'PENDING'})

def scan_report(request, task_id):
    """Retrieves data from Celery and formats it for the HTML report."""
    task_result = AsyncResult(task_id)
    
    # Ensure task actually finished successfully before rendering
    if task_result.state == 'SUCCESS':
        # Grab the live dictionary returned by your Celery task!
        scan_data = task_result.result 
        
        url = scan_data.get('url', 'Target Domain')
        
        # 1. Extract AI Risk Level
        risk_raw = scan_data.get('risk_category')
        if risk_raw is None:
            # Fallback for the dictionary format shown in your Celery logs
            ai_pred = scan_data.get('ai_prediction', {})
            risk_raw = ai_pred.get('risk_level', 'Low')

        # Convert to uppercase string for easy mapping
        if isinstance(risk_raw, int):
            int_to_str = {0: 'LOW', 1: 'MEDIUM', 2: 'HIGH', 3: 'CRITICAL'}
            risk_level_str = int_to_str.get(risk_raw, 'LOW')
        else:
            risk_level_str = str(risk_raw).upper()

        # 2. Map AI Risk Category to UI Variables
        ui_mapping = {
            'LOW': {'label': 'LOW RISK', 'score': 95, 'hex': '#4ADE80', 'text': 'text-green-400'},
            'MEDIUM': {'label': 'MEDIUM RISK', 'score': 75, 'hex': '#FDE047', 'text': 'text-yellow-300'},
            'HIGH': {'label': 'HIGH RISK', 'score': 40, 'hex': '#FB923C', 'text': 'text-orange-400'},
            'CRITICAL': {'label': 'CRITICAL RISK', 'score': 15, 'hex': '#F87171', 'text': 'text-red-400'}
        }
        risk_info = ui_mapping.get(risk_level_str, ui_mapping['LOW'])

        # 3. Extract Vulnerability Details
        vulnerability_details = scan_data.get('vulnerability_details', {})
        
        # Failsafe: Reconstruct the dictionary automatically from the vector
        if not vulnerability_details and 'vector' in scan_data:
            keys = [
                'missing_hsts', 'missing_x_frame_options', 'missing_x_content_type_options', 
                'missing_csp', 'exposed_server_header', 'exposed_x_powered_by', 
                'weak_ssl_certificate', 'exposed_dir_listing', 'missing_httponly_cookie', 
                'missing_secure_cookie', 'cors_wildcard', 'outdated_cms_header'
            ]
            vector = scan_data['vector']
            vulnerability_details = {keys[i]: bool(vector[i]) for i in range(min(len(keys), len(vector)))}

        # 4. Build the list of active vulnerabilities using utils.py
        found_vulns = []
        for key, is_vulnerable in vulnerability_details.items():
            if is_vulnerable and key in VULNERABILITY_DICT:
                found_vulns.append(VULNERABILITY_DICT[key])

        # 5. Build Context
        context = {
            'url': url,
            'risk_label': risk_info['label'],
            'risk_score': risk_info['score'],
            'score_hex': risk_info['hex'],
            'risk_text_color': risk_info['text'],
            'total_issues': len(found_vulns),
            'found_vulns': found_vulns,
            'raw_flags': vulnerability_details 
        }

        return render(request, 'websites/report.html', context)
        
    # Fallback if task failed or user navigated early
    return render(request, 'websites/report.html', {
        'url': 'Error',
        'risk_label': 'SCAN FAILED',
        'risk_score': 0,
        'score_hex': '#333333',
        'risk_text_color': 'text-slate-500',
        'total_issues': 0,
        'found_vulns': [],
        'raw_flags': {}
    })