from django.urls import path
from . import views


urlpatterns = [

    path(
        '',
        views.dashboard_view,
        name='dashboard'
    ),

    path(
        'scan/start/',
        views.start_scan_view,
        name='start_scan'
    ),

    path(
        'check-status/<str:task_id>/',
        views.check_scan_status,
        name='check_status'
    ),

    path(
        'report/<str:task_id>/',
        views.scan_report,
        name='scan_report'
    ),

    # HISTORY
    path(
        'history/',
        views.history_view,
        name='history'
    ),

    # REPORTS
    path(
        'reports/',
        views.reports_view,
        name='reports'
    ),
]