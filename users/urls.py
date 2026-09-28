from django.urls import path
from . import views

urlpatterns = [

    # USER
    path("register/", views.register, name="register"),
    path("login/", views.login, name="login"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("logout/", views.logout, name="logout"),
    path("profile/", views.profile_view, name="profile"),

    # OTP
    path("send-otp/", views.send_otp, name="send_otp"),
    path("verify-otp/", views.verify_otp, name="verify_otp"),

    # ADMIN
    path(
        "admin-login/",
        views.admin_login,
        name="admin_login"
    ),

    path(
        "admin-dashboard/",
        views.admin_dashboard,
        name="admin_dashboard"
    ),

    path(
        "admin-logout/",
        views.admin_logout,
        name="admin_logout"
    ),
path(
    "admin-users/",
    views.admin_users,
    name="admin_users"
),
path(
    "admin-users/<int:user_id>/",
    views.admin_user_detail,
    name="admin_user_detail"
),
path(
    "admin-scans/",
    views.admin_scans,
    name="admin_scans"
),
path(
    "admin-vulnerabilities/",
    views.admin_vulnerabilities,
    name="admin_vulnerabilities"
),
]