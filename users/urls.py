from django.urls import path
from . import views
from . import profile_views
from . import admin_views

urlpatterns = [
    path("register/", views.register, name="register"),
    path("login/", views.login, name="login"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("logout/", views.logout, name="logout"),
    
    # OTP
    path("send-otp/", views.send_otp, name="send_otp"),
    path("verify-otp/", views.verify_otp, name="verify_otp"),
    path("profile/", profile_views.profile_view, name="profile"),
    #UPDATES ABHI BRANCH
    path("admin-login/", admin_views.admin_login, name="admin_login"),
    path("admin-dashboard/", admin_views.admin_dashboard, name="admin_dashboard"),
    path("admin-users/", admin_views.admin_users, name="admin_users"),
    path(
        "admin-users/<int:user_id>/",
        admin_views.admin_user_detail,
        name="admin_user_detail"
    ),
    path("admin-scans/", admin_views.admin_scans, name="admin_scans"),
    path(
        "admin-vulnerabilities/",
        admin_views.admin_vulnerabilities,
        name="admin_vulnerabilities"
    ),
    path("admin-logout/", admin_views.admin_logout, name="admin_logout"),
]