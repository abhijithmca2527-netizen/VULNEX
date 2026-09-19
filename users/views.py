import re
import os
import requests

from dotenv import load_dotenv

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.http import JsonResponse

from .models import User

# Existing Supabase-backed VulnEx models
from websites.models import (
    Website,
    Scan,
    Vulnerability,
)


# ============================================================
# ENV
# ============================================================

load_dotenv()

API_KEY = os.getenv("TWOFACTOR_API_KEY")


# ============================================================
# SEND OTP
# ============================================================

def send_otp(request):

    mobile = request.POST.get("mobile")

    if not mobile:
        return JsonResponse(
            {
                "Status": "Error",
                "Details": "Mobile number is required."
            },
            status=400
        )

    url = (
        f"https://2factor.in/API/V1/"
        f"{API_KEY}/SMS/{mobile}/AUTOGEN2/OTP1"
    )

    try:

        response = requests.get(
            url,
            timeout=15
        )

        data = response.json()

    except Exception:

        return JsonResponse(
            {
                "Status": "Error",
                "Details": "Unable to send OTP."
            },
            status=500
        )

    if data.get("Status") == "Success":

        request.session["otp_session"] = (
            data.get("Details")
        )

    return JsonResponse(data)


# ============================================================
# VERIFY OTP
# ============================================================

def verify_otp(request):

    otp = request.POST.get("otp")

    session_id = request.session.get(
        "otp_session"
    )

    if not otp or not session_id:

        return JsonResponse(
            {
                "Status": "Error",
                "Details": "OTP session not found."
            },
            status=400
        )

    url = (
        f"https://2factor.in/API/V1/"
        f"{API_KEY}/SMS/VERIFY/"
        f"{session_id}/{otp}"
    )

    try:

        response = requests.get(
            url,
            timeout=15
        )

        data = response.json()

    except Exception:

        return JsonResponse(
            {
                "Status": "Error",
                "Details": "Unable to verify OTP."
            },
            status=500
        )

    if data.get("Status") == "Success":

        request.session["otp_verified"] = True

    return JsonResponse(data)


# ============================================================
# LANDING PAGE
# ============================================================

def landing_view(request):

    return render(
        request,
        "home/index.html"
    )


# ============================================================
# LOGIN
# ============================================================

def login(request):

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

            user = User.objects.get(
                email=email
            )

            if check_password(
                password,
                user.password
            ):

                request.session["user_id"] = (
                    user.pk
                )

                request.session["user_name"] = (
                    user.full_name
                )

                return redirect(
                    "dashboard"
                )

            else:

                messages.error(
                    request,
                    "Invalid password."
                )

        except User.DoesNotExist:

            messages.error(
                request,
                "Email not found."
            )

    return render(
        request,
        "auth/login.html"
    )


# ============================================================
# DASHBOARD
# ============================================================

def dashboard(request):

    if "user_id" not in request.session:

        return redirect(
            "login"
        )

    try:

        user = User.objects.get(
            pk=request.session["user_id"]
        )

    except User.DoesNotExist:

        request.session.flush()

        return redirect(
            "login"
        )

    return render(
        request,
        "dashboard/dashboard.html",
        {
            "user": user
        }
    )


# ============================================================
# LOGOUT
# ============================================================

def logout(request):

    request.session.flush()

    return redirect(
        "login"
    )


# ============================================================
# REGISTER
# ============================================================

def register(request):

    if request.method == "POST":

        full_name = request.POST.get(
            "full_name",
            ""
        ).strip()

        email = request.POST.get(
            "email",
            ""
        ).strip().lower()

        mobile = request.POST.get(
            "mobile_number",
            ""
        ).strip()

        password = request.POST.get(
            "password",
            ""
        )

        confirm_password = request.POST.get(
            "confirm_password",
            ""
        )

        # ----------------------------------------------------
        # REQUIRED FIELDS
        # ----------------------------------------------------

        if not all(
            [
                full_name,
                email,
                mobile,
                password,
                confirm_password
            ]
        ):

            messages.error(
                request,
                "All fields are required."
            )

            return redirect(
                "register"
            )

        # ----------------------------------------------------
        # FULL NAME
        # ----------------------------------------------------

        if len(full_name) < 3:

            messages.error(
                request,
                "Full name must contain at least 3 characters."
            )

            return redirect(
                "register"
            )

        if not full_name[0].isupper():

            messages.error(
                request,
                "Full name must start with a capital letter."
            )

            return redirect(
                "register"
            )

        if not re.fullmatch(
            r"[A-Za-z ]+",
            full_name
        ):

            messages.error(
                request,
                "Full name should contain only letters and spaces."
            )

            return redirect(
                "register"
            )

        # ----------------------------------------------------
        # EMAIL
        # ----------------------------------------------------

        email_pattern = (
            r"^[A-Za-z0-9._%+-]+"
            r"@[A-Za-z0-9.-]+"
            r"\.[A-Za-z]{2,}$"
        )

        if not re.fullmatch(
            email_pattern,
            email
        ):

            messages.error(
                request,
                "Enter a valid email address."
            )

            return redirect(
                "register"
            )

        if User.objects.filter(
            email=email
        ).exists():

            messages.error(
                request,
                "Email already registered."
            )

            return redirect(
                "register"
            )

        # ----------------------------------------------------
        # MOBILE
        # ----------------------------------------------------

        if not re.fullmatch(
            r"[6-9]\d{9}",
            mobile
        ):

            messages.error(
                request,
                "Enter a valid 10-digit mobile number."
            )

            return redirect(
                "register"
            )

        if User.objects.filter(
            mobile_number=mobile
        ).exists():

            messages.error(
                request,
                "Mobile number already registered."
            )

            return redirect(
                "register"
            )

        # ----------------------------------------------------
        # PASSWORD
        # ----------------------------------------------------

        if password != confirm_password:

            messages.error(
                request,
                "Passwords do not match."
            )

            return redirect(
                "register"
            )

        if len(password) < 6:

            messages.error(
                request,
                "Password must contain at least 6 characters."
            )

            return redirect(
                "register"
            )

        if not password[0].isupper():

            messages.error(
                request,
                "Password must start with a capital letter."
            )

            return redirect(
                "register"
            )

        if not re.search(
            r"\d",
            password
        ):

            messages.error(
                request,
                "Password must contain at least one number."
            )

            return redirect(
                "register"
            )

        if not re.search(
            r'[!@#$%^&*(),.?":{}|<>]',
            password
        ):

            messages.error(
                request,
                "Password must contain at least one special character."
            )

            return redirect(
                "register"
            )

        # ----------------------------------------------------
        # OTP
        # ----------------------------------------------------

        if not request.session.get(
            "otp_verified",
            False
        ):

            messages.error(
                request,
                "Please verify your mobile number first."
            )

            return redirect(
                "register"
            )

        # ----------------------------------------------------
        # CREATE USER
        # ----------------------------------------------------

        User.objects.create(

            full_name=full_name,

            email=email,

            mobile_number=mobile,

            password=make_password(
                password
            ),

            otp_verified=True
        )

        messages.success(
            request,
            "Registration Successful."
        )

        request.session.pop(
            "otp_session",
            None
        )

        request.session.pop(
            "otp_verified",
            None
        )

        return redirect(
            "login"
        )

    return render(
        request,
        "auth/register.html"
    )


# ============================================================
# PROFILE + HISTORY
# ============================================================

def profile_view(request):

    # --------------------------------------------------------
    # LOGIN CHECK
    # --------------------------------------------------------

    if "user_id" not in request.session:

        return redirect(
            "login"
        )

    try:

        user = User.objects.get(
            pk=request.session["user_id"]
        )

    except User.DoesNotExist:

        request.session.flush()

        return redirect(
            "login"
        )

    # ========================================================
    # PROFILE FORM ACTIONS
    # ========================================================

    if request.method == "POST":

        action = request.POST.get(
            "action"
        )

        # ====================================================
        # UPDATE PROFILE
        # ====================================================

        if action == "update_profile":

            full_name = request.POST.get(
                "full_name",
                ""
            ).strip()

            if len(full_name) < 3:

                messages.error(
                    request,
                    "Full name must contain at least 3 characters."
                )

                return redirect(
                    "profile"
                )

            if not re.fullmatch(
                r"[A-Za-z ]+",
                full_name
            ):

                messages.error(
                    request,
                    "Full name should contain only letters and spaces."
                )

                return redirect(
                    "profile"
                )

            user.full_name = full_name

            user.save(
                update_fields=[
                    "full_name"
                ]
            )

            request.session["user_name"] = (
                full_name
            )

            messages.success(
                request,
                "Profile updated successfully."
            )

            return redirect(
                "profile"
            )

        # ====================================================
        # CHANGE PASSWORD
        # ====================================================

        if action == "change_password":

            current_password = (
                request.POST.get(
                    "current_password",
                    ""
                )
            )

            new_password = (
                request.POST.get(
                    "new_password",
                    ""
                )
            )

            confirm_password = (
                request.POST.get(
                    "confirm_password",
                    ""
                )
            )

            # Current password
            if not check_password(
                current_password,
                user.password
            ):

                messages.error(
                    request,
                    "Current password is incorrect."
                )

                return redirect(
                    "profile"
                )

            # New / Confirm
            if new_password != confirm_password:

                messages.error(
                    request,
                    "New passwords do not match."
                )

                return redirect(
                    "profile"
                )

            # Minimum 8 characters
            if len(new_password) < 8:

                messages.error(
                    request,
                    "New password must contain at least 8 characters."
                )

                return redirect(
                    "profile"
                )

            # Uppercase
            if not re.search(
                r"[A-Z]",
                new_password
            ):

                messages.error(
                    request,
                    "Password must contain at least one uppercase letter."
                )

                return redirect(
                    "profile"
                )

            # Lowercase
            if not re.search(
                r"[a-z]",
                new_password
            ):

                messages.error(
                    request,
                    "Password must contain at least one lowercase letter."
                )

                return redirect(
                    "profile"
                )

            # Number
            if not re.search(
                r"\d",
                new_password
            ):

                messages.error(
                    request,
                    "Password must contain at least one number."
                )

                return redirect(
                    "profile"
                )

            # Special character
            if not re.search(
                r"[^A-Za-z0-9]",
                new_password
            ):

                messages.error(
                    request,
                    "Password must contain at least one special character."
                )

                return redirect(
                    "profile"
                )

            # Prevent same password
            if check_password(
                new_password,
                user.password
            ):

                messages.error(
                    request,
                    "New password cannot be the same as the current password."
                )

                return redirect(
                    "profile"
                )

            # Save hashed password
            user.password = make_password(
                new_password
            )

            user.save(
                update_fields=[
                    "password"
                ]
            )

            messages.success(
                request,
                "Password updated successfully."
            )

            return redirect(
                "profile"
            )

    # ========================================================
    # GET USER'S STORED SCANS FROM SUPABASE
    # ========================================================

    scans = (
        Scan.objects
        .select_related(
            "website"
        )
        .filter(
            website__user=user
        )
        .order_by(
            "-scan_date"
        )
    )

    # ========================================================
    # TOTAL SCANS
    # ========================================================

    total_scans = (
        scans.count()
    )

    # ========================================================
    # UNIQUE WEBSITES
    # ========================================================

    unique_websites = (
        Website.objects
        .filter(
            user=user
        )
        .values(
            "website_url"
        )
        .distinct()
        .count()
    )

    # ========================================================
    # GRAPH + CALENDAR DATA
    # ========================================================

    history_data = {}

    all_scores = []

    for scan in scans:

        # ----------------------------------------------------
        # FINDINGS
        # ----------------------------------------------------

        findings = (
            Vulnerability.objects
            .filter(
                scan=scan
            )
            .count()
        )

        # ----------------------------------------------------
        # CONSISTENT HEALTH SCORE
        #
        # 0 findings = 100
        # 1 finding  = 92
        # 2 findings = 84
        # 3 findings = 76
        # 4 findings = 68
        # ----------------------------------------------------

        score = max(
            0,
            100 - (findings * 8)
        )

        all_scores.append(
            score
        )

        # ----------------------------------------------------
        # WEBSITE
        # ----------------------------------------------------

        target = (
            scan.website.website_url
        )

        if target not in history_data:

            history_data[target] = []

        # ----------------------------------------------------
        # ONE SCAN RECORD
        # ----------------------------------------------------

        history_data[target].append({

            "date":
                scan.scan_date.strftime(
                    "%Y-%m-%d"
                ),

            "datetime":
                scan.scan_date.isoformat(),

            "display_datetime":
                scan.scan_date.strftime(
                    "%d %b %Y, %I:%M %p"
                ),

            "score":
                score,

            "findings":
                findings,

            "risk":
                scan.risk_level
                or "Unknown",

            # Confidence is not currently stored
            # inside the SCANS Supabase table.
            "confidence":
                0,

            "scan_id":
                scan.scan_id,

            # Existing profile JavaScript expects task_id.
            # For saved scans we use the permanent scan_id.
            "task_id":
                scan.scan_id,
        })

    # ========================================================
    # OVERALL SECURITY SCORE
    # ========================================================

    if all_scores:

        overall_score = round(
            sum(all_scores)
            / len(all_scores)
        )

    else:

        overall_score = 100

    # ========================================================
    # RECENT SCANS
    # ========================================================

    recent_scan_objects = (
        Scan.objects
        .select_related(
            "website"
        )
        .filter(
            website__user=user
        )
        .order_by(
            "-scan_date"
        )[:10]
    )

    recent_scans = []

    for scan in recent_scan_objects:

        findings = (
            Vulnerability.objects
            .filter(
                scan=scan
            )
            .count()
        )

        display_score = max(
            0,
            100 - (findings * 8)
        )

        recent_scans.append({

            "scan_id":
                scan.scan_id,

            "task_id":
                scan.scan_id,

            "target_url":
                scan.website.website_url,

            "created_at":
                scan.scan_date,

            "risk_level":
                scan.risk_level
                or "Unknown",

            "security_score":
                display_score,

            "confidence":
                0,

            "findings":
                findings,
        })

    # ========================================================
    # PROFILE CONTEXT
    # ========================================================

    context = {

        "user":
            user,

        "total_scans":
            total_scans,

        "unique_websites":
            unique_websites,

        "overall_score":
            overall_score,

        "recent_scans":
            recent_scans,

        "history_data":
            history_data,
    }

    return render(
        request,
        "profile/profile.html",
        context
    )