from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
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
            task = run_vulnex_scan.delay(target_url)
            return render(request, 'websites/loading.html', {
                'task_id': task.id, 
                'target_url': target_url
            })
    return redirect('dashboard')

def check_scan_status(request, task_id):
    """API endpoint queried periodically to check task completion."""
    task_result = AsyncResult(task_id)
    if task_result.state == 'SUCCESS':
        return JsonResponse({'status': 'SUCCESS'})
    elif task_result.state == 'FAILURE':
        return JsonResponse({'status': 'FAILURE'})
    return JsonResponse({'status': 'PENDING'})

def scan_report(request, task_id):
    """Retrieves scan output from Celery and compiles dynamic context for report.html."""
    task_result = AsyncResult(task_id)
    
    if task_result.state == 'SUCCESS':
        scan_data = task_result.result 
        url = scan_data.get('url', 'Target Domain')
        source = scan_data.get('source', 'Random Forest')

        # Handle Tier 2 (Ollama LLM) Scans
        if source == 'Ollama LLM':
            score = scan_data.get('score', 100)
            risk_label = scan_data.get('risk', 'Clean')
            novel_details = scan_data.get('details', 'No anomalies found.')

            if score < 50:
                hex_color, text_color = '#F87171', 'text-red-400'
            elif score < 85:
                hex_color, text_color = '#FB923C', 'text-orange-400'
            else:
                hex_color, text_color = '#4ADE80', 'text-green-400'

            context = {
                'url': url,
                'engine': 'Ollama LLM (Llama 3)',
                'risk_label': risk_label,
                'risk_score': score,
                'score_hex': hex_color,
                'risk_text_color': text_color,
                'total_issues': 0 if risk_label == 'Clean' else 1,
                'is_ollama': True,
                'novel_details': novel_details,
                'found_vulns': [],
                'raw_flags': {}
            }
            return render(request, 'websites/report.html', context)

        # Handle Tier 1 (Random Forest) Scans
        risk_raw = scan_data.get('risk_category')
        if risk_raw is None:
            ai_pred = scan_data.get('ai_prediction', {})
            risk_raw = ai_pred.get('risk_level', 'Low')

        if isinstance(risk_raw, int):
            int_to_str = {0: 'LOW', 1: 'MEDIUM', 2: 'HIGH', 3: 'CRITICAL'}
            risk_level_str = int_to_str.get(risk_raw, 'LOW')
        else:
            risk_level_str = str(risk_raw).upper()

        ui_mapping = {
            'LOW': {'label': 'LOW RISK', 'score': 95, 'hex': '#4ADE80', 'text': 'text-green-400'},
            'MEDIUM': {'label': 'MEDIUM RISK', 'score': 75, 'hex': '#FDE047', 'text': 'text-yellow-300'},
            'HIGH': {'label': 'HIGH RISK', 'score': 40, 'hex': '#FB923C', 'text': 'text-orange-400'},
            'CRITICAL': {'label': 'CRITICAL RISK', 'score': 15, 'hex': '#F87171', 'text': 'text-red-400'}
        }
        risk_info = ui_mapping.get(risk_level_str, ui_mapping['LOW'])

        vulnerability_details = scan_data.get('vulnerability_details', {})
        if not vulnerability_details and 'vector' in scan_data:
            keys = [
                'missing_hsts', 'missing_x_frame_options', 'missing_x_content_type_options', 
                'missing_csp', 'exposed_server_header', 'exposed_x_powered_by', 
                'weak_ssl_certificate', 'exposed_dir_listing', 'missing_httponly_cookie', 
                'missing_secure_cookie', 'cors_wildcard', 'outdated_cms_header'
            ]
            vector = scan_data['vector']
            vulnerability_details = {keys[i]: bool(vector[i]) for i in range(min(len(keys), len(vector)))}

        found_vulns = [
            VULNERABILITY_DICT[key]
            for key, is_vulnerable in vulnerability_details.items()
            if is_vulnerable and key in VULNERABILITY_DICT
        ]

        context = {
            'url': url,
            'engine': 'Random Forest Classifier',
            'risk_label': risk_info['label'],
            'risk_score': risk_info['score'],
            'score_hex': risk_info['hex'],
            'risk_text_color': risk_info['text'],
            'total_issues': len(found_vulns),
            'is_ollama': False,
            'novel_details': '',
            'found_vulns': found_vulns,
            'raw_flags': vulnerability_details 
        }
        return render(request, 'websites/report.html', context)
        
    return render(request, 'websites/report.html', {
        'url': 'Error',
        'engine': 'Unknown',
        'risk_label': 'SCAN FAILED',
        'risk_score': 0,
        'score_hex': '#333333',
        'risk_text_color': 'text-slate-500',
        'total_issues': 0,
        'is_ollama': False,
        'novel_details': '',
        'found_vulns': [],
        'raw_flags': {}
    })

def zero_day_test_target(request):
    """Honeypot target with baseline headers and simulated novel disclosure."""
    response = HttpResponse("Vulnex Tier 2 Honeypot Target")
    response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response['X-Frame-Options'] = 'DENY'
    response['X-Content-Type-Options'] = 'nosniff'
    response['Content-Security-Policy'] = "default-src 'self'"
    response['Set-Cookie'] = 'session=trusted; HttpOnly; Secure'
    response['X-Backend-Database-IP'] = '10.240.5.112'
    response['X-Debug-API-Token'] = 'vulnex_admin_secret_9942'
    return response