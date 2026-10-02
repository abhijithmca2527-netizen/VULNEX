from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import check_password

from .models import User

from websites.models import (
    Website,
    ScanResult,
    Vulnerability,
)

# ============================================================
# ADMIN LOGIN
# ============================================================

def admin_login(request):

    # --------------------------------------------------------
    # ALWAYS SHOW A FRESH ADMIN LOGIN FORM ON GET
    # --------------------------------------------------------

    if request.method == "GET":

        request.session.pop(
            "admin_user_id",
            None
        )

        request.session.pop(
            "admin_name",
            None
        )

    # --------------------------------------------------------
    # ADMIN LOGIN FORM SUBMISSION
    # --------------------------------------------------------

    if request.method == "POST":

        email = request.POST.get(
            "email",
            ""
        ).strip().lower()

        password = request.POST.get(
            "password",
            ""
        )

        try:

            admin = User.objects.get(
                email=email,
                role="admin"
            )

            if check_password(
                password,
                admin.password
            ):

                # Separate admin session
                request.session["admin_user_id"] = (
                    admin.pk
                )

                request.session["admin_name"] = (
                    admin.full_name
                )

                # Expire the admin session when the browser closes
                request.session.set_expiry(0)

                return redirect(
                    "admin_dashboard"
                )

            else:

                messages.error(
                    request,
                    "Invalid admin password."
                )

        except User.DoesNotExist:

            messages.error(
                request,
                "Invalid administrator account."
            )

    return render(
        request,
        "admin/admin_login.html"
    )

# ============================================================
# ADMIN DASHBOARD
# ============================================================

def admin_dashboard(request):

    # --------------------------------------------------------
    # ADMIN SESSION CHECK
    # --------------------------------------------------------

    admin_id = request.session.get(
        "admin_user_id"
    )

    if not admin_id:

        return redirect(
            "admin_login"
        )

    try:

        admin = User.objects.get(
            pk=admin_id,
            role="admin"
        )

    except User.DoesNotExist:

        request.session.pop(
            "admin_user_id",
            None
        )

        request.session.pop(
            "admin_name",
            None
        )

        return redirect(
            "admin_login"
        )

    # --------------------------------------------------------
    # DASHBOARD COUNTS
    # --------------------------------------------------------

    total_users = (
        User.objects
        .filter(role="user")
        .count()
    )

    total_websites = (
        Website.objects
        .count()
    )

    total_scans = (
        ScanResult.objects
        .count()
    )

    total_vulnerabilities = Vulnerability.objects.count()

    # --------------------------------------------------------
    # RECENT SCANS
    # --------------------------------------------------------

    recent_scans = (
        ScanResult.objects

        .order_by(
            "-scan_date"
        )[:10]
    )

    context = {

        "admin":
            admin,

        "total_users":
            total_users,

        "total_websites":
            total_websites,

        "total_scans":
            total_scans,

        "total_vulnerabilities":
            total_vulnerabilities,

        "recent_scans":
            recent_scans,
    }

    return render(
        request,
        "admin/admin_dashboard.html",
        context
    )


# ============================================================
# ADMIN LOGOUT
# ============================================================

def admin_logout(request):

    request.session.pop(
        "admin_user_id",
        None
    )

    request.session.pop(
        "admin_name",
        None
    )

    return redirect(
        "admin_login"
    )
# ============================================================
# ADMIN - USER MANAGEMENT
# ============================================================

def admin_users(request):

    # --------------------------------------------------------
    # ADMIN LOGIN CHECK
    # --------------------------------------------------------

    admin_id = request.session.get(
        "admin_user_id"
    )

    if not admin_id:

        return redirect(
            "admin_login"
        )

    try:

        admin = User.objects.get(
            pk=admin_id,
            role="admin"
        )

    except User.DoesNotExist:

        request.session.pop(
            "admin_user_id",
            None
        )

        request.session.pop(
            "admin_name",
            None
        )

        return redirect(
            "admin_login"
        )

    # --------------------------------------------------------
    # GET NORMAL USERS
    # --------------------------------------------------------

    users = (
        User.objects
        .filter(
            role="user"
        )
        .order_by(
            "-created_at"
        )
    )

    # --------------------------------------------------------
    # USER ACTIVITY COUNTS
    # --------------------------------------------------------

    user_data = []

    for user in users:

        website_count = (
            Website.objects
            .filter(
                user_id=user.user_id
            )
            .count()
        )

        scan_count = (
            ScanResult.objects
            .filter(
                user=user
            )
            .count()
        )

        vulnerability_count = Vulnerability.objects.filter(
            scan__user=user
        ).count()

        user_data.append({

            "user":
                user,

            "website_count":
                website_count,

            "scan_count":
                scan_count,

            "vulnerability_count":
                vulnerability_count,
        })

    return render(
        request,
        "admin/admin_users.html",
        {
            "admin": admin,
            "user_data": user_data,
        }
    )
# ============================================================
# ADMIN - USER DETAILS
# ============================================================

def admin_user_detail(request, user_id):

    # --------------------------------------------------------
    # ADMIN LOGIN CHECK
    # --------------------------------------------------------

    admin_id = request.session.get(
        "admin_user_id"
    )

    if not admin_id:

        return redirect(
            "admin_login"
        )

    try:

        admin = User.objects.get(
            pk=admin_id,
            role="admin"
        )

    except User.DoesNotExist:

        request.session.pop(
            "admin_user_id",
            None
        )

        request.session.pop(
            "admin_name",
            None
        )

        return redirect(
            "admin_login"
        )

    # --------------------------------------------------------
    # GET SELECTED USER
    # --------------------------------------------------------

    try:

        selected_user = User.objects.get(
            pk=user_id,
            role="user"
        )

    except User.DoesNotExist:

        messages.error(
            request,
            "User not found."
        )

        return redirect(
            "admin_users"
        )

    # --------------------------------------------------------
    # USER WEBSITES
    # --------------------------------------------------------

    websites = (
        Website.objects
        .filter(
            user_id=selected_user.user_id
        )
        .order_by(
            "-added_date"
        )
    )

    # --------------------------------------------------------
    # USER SCANS
    # --------------------------------------------------------

    scans = (
        ScanResult.objects

        .filter(
            user=selected_user
        )
        .order_by(
            "-scan_date"
        )
    )

    # --------------------------------------------------------
    # PREPARE SCAN DETAILS
    # --------------------------------------------------------

    scan_data = []

    for scan in scans:

        findings = Vulnerability.objects.filter(
            scan=scan
        ).count()

        # ----------------------------------------------------
        # USE STORED SECURITY SCORE
        # ----------------------------------------------------

        if scan.security_score is not None:

            score = scan.security_score

        else:

            score = max(
                0,
                100 - (findings * 8)
            )

        scan_data.append({

            "scan":
                scan,

            "findings":
                findings,

            "display_score":
                score,
        })

    # --------------------------------------------------------
    # TOTALS
    # --------------------------------------------------------

    total_websites = (
        websites.count()
    )

    total_scans = (
        scans.count()
    )

    total_findings = Vulnerability.objects.filter(
        scan__user=selected_user
    ).count()

    # --------------------------------------------------------
    # CONTEXT
    # --------------------------------------------------------

    context = {

        "admin":
            admin,

        "selected_user":
            selected_user,

        "websites":
            websites,

        "scan_data":
            scan_data,

        "total_websites":
            total_websites,

        "total_scans":
            total_scans,

        "total_findings":
            total_findings,
    }

    return render(
        request,
        "admin/admin_user_detail.html",
        context
    )

# ============================================================
# ADMIN - SCAN MANAGEMENT
# ============================================================

def admin_scans(request):

    # --------------------------------------------------------
    # ADMIN LOGIN CHECK
    # --------------------------------------------------------

    admin_id = request.session.get(
        "admin_user_id"
    )

    if not admin_id:

        return redirect(
            "admin_login"
        )

    try:

        admin = User.objects.get(
            pk=admin_id,
            role="admin"
        )

    except User.DoesNotExist:

        request.session.pop(
            "admin_user_id",
            None
        )

        request.session.pop(
            "admin_name",
            None
        )

        return redirect(
            "admin_login"
        )

    # --------------------------------------------------------
    # GET ALL SCANS
    # --------------------------------------------------------

    scans = (
        ScanResult.objects

        .order_by(
            "-scan_date"
        )
    )

    # --------------------------------------------------------
    # PREPARE SCAN DATA
    # --------------------------------------------------------

    scan_data = []

    for scan in scans:

        # Count vulnerability rows actually saved for this scan.
        findings = Vulnerability.objects.filter(
            scan=scan
        ).count()

        # Use the score saved when the scan was created.
        # Only calculate a fallback score for older rows where
        # security_score is missing.
        if scan.security_score is not None:

            score = scan.security_score

        else:

            score = max(
                0,
                100 - (findings * 8)
            )

        scan_data.append({

            "scan":
                scan,

            "findings":
                findings,

            "display_score":
                score,
        })

    context = {

        "admin":
            admin,

        "scan_data":
            scan_data,

        "total_scans":
            scans.count(),
    }

    return render(
        request,
        "admin/admin_scans.html",
        context
    )
# ============================================================
# ADMIN - VULNERABILITY RECORDS
# ============================================================

def admin_vulnerabilities(request):

    # --------------------------------------------------------
    # ADMIN LOGIN CHECK
    # --------------------------------------------------------

    admin_id = request.session.get(
        "admin_user_id"
    )

    if not admin_id:

        return redirect(
            "admin_login"
        )

    try:

        admin = User.objects.get(
            pk=admin_id,
            role="admin"
        )

    except User.DoesNotExist:

        request.session.pop(
            "admin_user_id",
            None
        )

        request.session.pop(
            "admin_name",
            None
        )

        return redirect(
            "admin_login"
        )

    # --------------------------------------------------------
    # GET ALL VULNERABILITIES
    # --------------------------------------------------------

    vulnerabilities = (
        Vulnerability.objects
        .select_related("scan", "scan__user")
        .order_by("-vulnerability_id")
    )

    context = {

        "admin":
            admin,

        "vulnerabilities":
            vulnerabilities,

        "total_vulnerabilities":
            vulnerabilities.count(),
    }

    return render(
        request,
        "admin/admin_vulnerabilities.html",
        context
    )
