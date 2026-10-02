from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from celery.result import AsyncResult
from .tasks import run_vulnex_scan
from .utils import VULNERABILITY_DICT
from .models import Website
from urllib.parse import urlparse

def dashboard_view(request):
    """Renders the main dashboard template."""
    return render(request, 'dashboard.html')

def start_scan_view(request):
    """Handles URL submission, saves to DB, sends job to Celery, and loads the spinner."""
    if request.method == "POST":
        target_url = request.POST.get("target_url")
        if target_url:
            # Parse the domain for the website_name column
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc or parsed_url.path

            # Assign a fallback user_id of 1 if not authenticated
            current_user_id = request.session.get("user_id")
            if not current_user_id:
                return redirect("login")
            # Query using the exact field names from the updated model
            website, created = Website.objects.get_or_create(
                website_url=target_url,
                defaults={
                    'website_name': domain,
                    'user_id': current_user_id
                }
            )

            # Pass the dynamic database ID (website_id) to the Celery task
            task = run_vulnex_scan.delay(target_url, website_id=website.website_id,user_id=current_user_id)
            
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

        # USE DYNAMIC SCORE FROM CELERY TASK
        actual_score = scan_data.get('score', 100)

        # Risk level is determined ONLY from the final security score.
        # This keeps the report consistent with the stored scan score.
        if actual_score >= 100:
            risk_label_str = 'CLEAN'
        elif actual_score >= 70:
            risk_label_str = 'LOW RISK'
        elif actual_score >= 40:
            risk_label_str = 'MEDIUM RISK'
        else:
            risk_label_str = 'HIGH RISK'

        # Dynamic color styling based on the actual score
        if actual_score >= 80:
            hex_color, text_color = '#4ADE80', 'text-green-400'
        elif actual_score >= 60:
            hex_color, text_color = '#FDE047', 'text-yellow-300'
        elif actual_score >= 40:
            hex_color, text_color = '#FB923C', 'text-orange-400'
        else:
            hex_color, text_color = '#F87171', 'text-red-400'

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

        not_detected_vulns = [
            VULNERABILITY_DICT[key]
            for key, is_vulnerable in vulnerability_details.items()
            if not is_vulnerable and key in VULNERABILITY_DICT
        ]

        context = {
            'url': url,
            'engine': 'Random Forest Classifier',
            'risk_label': risk_label_str,
            'risk_score': actual_score,
            'score_hex': hex_color,
            'risk_text_color': text_color,
            'total_issues': len(found_vulns),
            'total_passed': len(not_detected_vulns),
            'is_ollama': False,
            'novel_details': '',
            'found_vulns': found_vulns,
            'not_detected_vulns': not_detected_vulns,
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