import re

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password

from .models import User

from websites.models import (
    Website,
    ScanResult,
    Vulnerability,
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
        ScanResult.objects
        .filter(
            user_id=user.user_id
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
            user_id=user.user_id
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

        findings = Vulnerability.objects.filter(
            scan_id=scan.scan_id
        ).count()

        # ----------------------------------------------------
        # CONSISTENT HEALTH SCORE
        #
        # 0 findings = 100
        # 1 finding  = 92
        # 2 findings = 84
        # 3 findings = 76
        # 4 findings = 68
        # ----------------------------------------------------

        score = (
            scan.security_score
            if scan.security_score is not None
            else 0
        )

        all_scores.append(
            score
        )

        # ----------------------------------------------------
        # WEBSITE
        # ----------------------------------------------------

        website = Website.objects.filter(
            website_id=scan.website_id
        ).first()

        target = (
            website.website_url
            if website
            else f"Website #{scan.website_id}"
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
        ScanResult.objects
        .filter(
            user_id=user.user_id
        )
        .order_by(
            "-scan_date"
        )[:10]
    )

    recent_scans = []

    for scan in recent_scan_objects:

        findings = Vulnerability.objects.filter(
            scan_id=scan.scan_id
        ).count()

        display_score = (
            scan.security_score
            if scan.security_score is not None
            else 0
        )

        recent_scans.append({

            "scan_id":
                scan.scan_id,

            "task_id":
                scan.scan_id,

            "target_url": (
                Website.objects
                .filter(website_id=scan.website_id)
                .values_list("website_url", flat=True)
                .first()
                or f"Website #{scan.website_id}"
            ),

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
