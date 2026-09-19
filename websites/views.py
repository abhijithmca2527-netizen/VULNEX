from django.shortcuts import render, redirect
from django.http import JsonResponse
from celery.result import AsyncResult

from .tasks import run_vulnex_scan
from .utils import VULNERABILITY_DICT
from .ml_engine import VulnexAIEngine
from django.urls import reverse
from .models import Scan, Vulnerability


def dashboard_view(request):
    """Renders the main dashboard template."""
    return render(
        request,
        "dashboard.html"
    )


def start_scan_view(request):
    """
    Handles URL submission,
    sends the scan to Celery with the logged-in user ID,
    and loads the spinner page.
    """

    if request.method == "POST":

        target_url = request.POST.get(
            "target_url"
        )

        user_id = request.session.get(
            "user_id"
        )

        if not user_id:
            return redirect(
                "login"
            )

        if target_url:

            # Pass target URL + logged-in user ID
            # so the Celery task can save scan data to Supabase.
            task = run_vulnex_scan.delay(
                target_url,
                user_id
            )

            return render(
                request,
                "websites/loading.html",
                {
                    "task_id": task.id,
                    "target_url": target_url,
                }
            )

    return redirect(
        "dashboard"
    )

def check_scan_status(request, task_id):
    """
    Loading screen checks this endpoint
    until Celery finishes the scan.
    """

    task_result = AsyncResult(
        task_id
    )

    if task_result.state == "SUCCESS":

        return JsonResponse(
            {
                "status": "SUCCESS"
            }
        )

    elif task_result.state == "FAILURE":

        return JsonResponse(
            {
                "status": "FAILURE"
            }
        )

    return JsonResponse(
        {
            "status": "PENDING"
        }
    )




FEATURE_KEYS = [
    "missing_hsts",
    "missing_x_frame_options",
    "missing_x_content_type_options",
    "missing_csp",
    "exposed_server_header",
    "exposed_x_powered_by",
    "weak_ssl_certificate",
    "exposed_dir_listing",
    "missing_httponly_cookie",
    "missing_secure_cookie",
    "cors_wildcard",
    "outdated_cms_header",
]


def rebuild_saved_scan_vector(scan):
    """
    Rebuild the 12-bit vector from saved VULNERABILITIES rows.
    This lets old saved reports show current-model confidence
    without adding a new database column.
    """

    stored_names = {
        str(name).strip().lower()
        for name in (
            Vulnerability.objects
            .filter(scan=scan)
            .values_list("vulnerability_name", flat=True)
        )
    }

    vector = []

    for key in FEATURE_KEYS:

        info = VULNERABILITY_DICT.get(
            key,
            {}
        )

        expected_name = str(
            info.get("name", "")
        ).strip().lower()

        vector.append(
            1 if expected_name in stored_names else 0
        )

    return vector


def recompute_saved_confidence(scan):
    """
    Confidence is not stored in the current SCANS table.
    Recompute it from the saved vulnerability vector.
    """

    try:

        vector = rebuild_saved_scan_vector(
            scan
        )

        result = (
            VulnexAIEngine()
            .predict_risk(vector)
        )

        return round(
            float(
                result.get(
                    "confidence",
                    0
                )
            ),
            2
        )

    except Exception:

        return 0


# ============================================================
# BUILD REPORT CONTEXT FROM A SAVED SUPABASE SCAN
# ============================================================

def build_database_report_context(scan):
    """
    Builds the same report.html context from a permanent
    SCANS + VULNERABILITIES record in Supabase.
    """

    vulnerabilities = (
        Vulnerability.objects
        .filter(scan=scan)
        .order_by("vulnerability_id")
    )

    found_vulns = []
    raw_flags = {}

    for vulnerability in vulnerabilities:

        matched_key = None
        vuln_data = None

        # Match the stored vulnerability name back to utils.py
        # so the saved report keeps the same description/fix.
        for key, data in VULNERABILITY_DICT.items():

            if (
                str(data.get("name", "")).strip().lower()
                ==
                str(vulnerability.vulnerability_name).strip().lower()
            ):
                matched_key = key
                vuln_data = data.copy()
                break

        # Fallback for older/custom stored findings.
        if vuln_data is None:

            vuln_data = {
                "name":
                    vulnerability.vulnerability_name,

                "description":
                    vulnerability.description
                    or "Security weakness detected during passive analysis.",

                "fix":
                    "Review and apply the recommended security configuration.",
            }

        # Prefer the exact stored database description when available.
        if vulnerability.description:

            vuln_data["description"] = (
                vulnerability.description
            )

        # IMPORTANT:
        # Restore the stored Issue/evidence column.
        vuln_data["issue"] = (
            vulnerability.issue
            or "Issue detected during passive security analysis."
        )

        if matched_key:

            vuln_data["key"] = matched_key
            raw_flags[matched_key] = True

        found_vulns.append(
            vuln_data
        )

    # --------------------------------------------------------
    # RISK STYLE
    # --------------------------------------------------------

    risk_level = str(
        scan.risk_level
        or "UNKNOWN"
    ).strip().upper()

    ui_mapping = {

        "LOW": {
            "label": "LOW RISK",
            "hex": "#4ADE80",
            "text": "text-green-400",
        },

        "MEDIUM": {
            "label": "MEDIUM RISK",
            "hex": "#FDE047",
            "text": "text-yellow-300",
        },

        "HIGH": {
            "label": "HIGH RISK",
            "hex": "#FB923C",
            "text": "text-orange-400",
        },

        "CRITICAL": {
            "label": "CRITICAL RISK",
            "hex": "#F87171",
            "text": "text-red-400",
        },

        "UNKNOWN": {
            "label": "UNKNOWN RISK",
            "hex": "#64748B",
            "text": "text-slate-400",
        },
    }

    risk_info = ui_mapping.get(
        risk_level,
        ui_mapping["UNKNOWN"]
    )

    # --------------------------------------------------------
    # HEALTH SCORE + CONFIDENCE FOR SAVED REPORT
    # --------------------------------------------------------

    security_score = max(
        0,
        100 - (len(found_vulns) * 8)
    )

    confidence = recompute_saved_confidence(
        scan
    )

    return {

        "url":
            scan.website.website_url,

        "risk_label":
            risk_info["label"],

        "risk_score":
            security_score,

        "score_hex":
            risk_info["hex"],

        "risk_text_color":
            risk_info["text"],

        "confidence":
            confidence,

        "total_issues":
            len(found_vulns),

        "found_vulns":
            found_vulns,

        "raw_flags":
            raw_flags,

        "issues": {
            item.get("key", f"finding_{index}"):
                item.get("issue", "")
            for index, item in enumerate(found_vulns)
        },

        "scan_id":
            scan.pk,

        "created_at":
            scan.scan_date,
    }


def scan_report(request, task_id):
    """
    Opens BOTH:
    1. A fresh Celery report using its UUID.
    2. A saved Supabase report using its numeric scan ID.
    """

    if "user_id" not in request.session:
        return redirect(
            "login"
        )

    user_id = request.session.get(
        "user_id"
    )

    identifier = str(
        task_id
    ).strip()

    # =====================================================
    # SAVED DATABASE REPORT
    # /report/63/
    # =====================================================

    if identifier.isdigit():

        try:

            scan = (
                Scan.objects
                .select_related("website")
                .get(
                    pk=int(identifier),
                    website__user_id=user_id
                )
            )

            context = (
                build_database_report_context(
                    scan
                )
            )

            return render(
                request,
                "websites/report.html",
                context
            )

        except Scan.DoesNotExist:

            return render(
                request,
                "websites/report.html",
                {
                    "url":
                        "Report Not Found",

                    "risk_label":
                        "REPORT UNAVAILABLE",

                    "risk_score":
                        0,

                    "score_hex":
                        "#475569",

                    "risk_text_color":
                        "text-slate-500",

                    "confidence":
                        0,

                    "total_issues":
                        0,

                    "found_vulns":
                        [],

                    "raw_flags":
                        {},

                    "issues":
                        {},
                }
            )

    # =====================================================
    # FRESH CELERY REPORT
    # /report/<uuid>/
    # =====================================================

    task_result = AsyncResult(
        identifier
    )

    # =====================================================
    # SUCCESSFUL SCAN
    # =====================================================

    if task_result.state == "SUCCESS":

        scan_data = task_result.result

        if not isinstance(
            scan_data,
            dict
        ):
            scan_data = {}

        # =================================================
        # TARGET URL
        # =================================================

        url = scan_data.get(
            "url",
            "Target Domain"
        )

        # =================================================
        # AI PREDICTION
        # =================================================

        ai_prediction = scan_data.get(
            "ai_prediction",
            {}
        )

        if not isinstance(
            ai_prediction,
            dict
        ):
            ai_prediction = {}

        risk_raw = scan_data.get(
            "risk_category"
        )

        if risk_raw is None:

            risk_raw = ai_prediction.get(
                "risk_level",
                "Low"
            )

        # Convert numeric class to name
        if isinstance(
            risk_raw,
            int
        ):

            int_to_str = {
                0: "LOW",
                1: "MEDIUM",
                2: "HIGH",
                3: "CRITICAL",
            }

            risk_level_str = (
                int_to_str.get(
                    risk_raw,
                    "LOW"
                )
            )

        else:

            risk_level_str = (
                str(
                    risk_raw
                )
                .strip()
                .upper()
            )

        # =================================================
        # UI RISK STYLE
        # =================================================

        ui_mapping = {

            "LOW": {
                "label":
                    "LOW RISK",

                "score":
                    95,

                "hex":
                    "#4ADE80",

                "text":
                    "text-green-400",
            },

            "MEDIUM": {
                "label":
                    "MEDIUM RISK",

                "score":
                    75,

                "hex":
                    "#FDE047",

                "text":
                    "text-yellow-300",
            },

            "HIGH": {
                "label":
                    "HIGH RISK",

                "score":
                    40,

                "hex":
                    "#FB923C",

                "text":
                    "text-orange-400",
            },

            "CRITICAL": {
                "label":
                    "CRITICAL RISK",

                "score":
                    15,

                "hex":
                    "#F87171",

                "text":
                    "text-red-400",
            },
        }

        risk_info = ui_mapping.get(
            risk_level_str,
            ui_mapping["LOW"]
        )

        # =================================================
        # SECURITY SCORE
        # =================================================

        # Use real security score from task if available.
        # Otherwise keep existing UI fallback score.
        security_score = scan_data.get(
            "security_score"
        )

        if security_score is None:

            security_score = (
                ai_prediction.get(
                    "security_score"
                )
            )

        if security_score is None:

            security_score = (
                risk_info["score"]
            )

        # =================================================
        # MODEL CONFIDENCE
        # =================================================

        confidence = scan_data.get(
            "confidence"
        )

        if confidence is None:

            confidence = (
                ai_prediction.get(
                    "confidence",
                    0
                )
            )

        try:
            confidence = round(
                float(confidence),
                2
            )

        except (
            TypeError,
            ValueError
        ):
            confidence = 0

        # =================================================
        # VULNERABILITY DETAILS
        # =================================================

        vulnerability_details = (
            scan_data.get(
                "vulnerability_details",
                {}
            )
        )

        if not isinstance(
            vulnerability_details,
            dict
        ):
            vulnerability_details = {}

        # =================================================
        # SITE-SPECIFIC ISSUES / EVIDENCE
        # =================================================

        issues = scan_data.get(
            "issues",
            {}
        )

        if not isinstance(
            issues,
            dict
        ):
            issues = {}

        # =================================================
        # VECTOR FALLBACK
        # =================================================

        if (
            not vulnerability_details
            and "vector" in scan_data
        ):

            keys = [
                "missing_hsts",
                "missing_x_frame_options",
                "missing_x_content_type_options",
                "missing_csp",
                "exposed_server_header",
                "exposed_x_powered_by",
                "weak_ssl_certificate",
                "exposed_dir_listing",
                "missing_httponly_cookie",
                "missing_secure_cookie",
                "cors_wildcard",
                "outdated_cms_header",
            ]

            vector = scan_data.get(
                "vector",
                []
            )

            vulnerability_details = {
                keys[i]:
                    bool(
                        vector[i]
                    )

                for i in range(
                    min(
                        len(keys),
                        len(vector)
                    )
                )
            }

        # =================================================
        # BUILD DETECTED VULNERABILITY LIST
        # =================================================

        found_vulns = []

        for (
            key,
            is_vulnerable
        ) in vulnerability_details.items():

            if not is_vulnerable:
                continue

            if key not in VULNERABILITY_DICT:
                continue

            # COPY so VULNERABILITY_DICT itself
            # is never modified.
            vuln_data = (
                VULNERABILITY_DICT[
                    key
                ].copy()
            )

            # Keep vulnerability key available
            vuln_data[
                "key"
            ] = key

            # IMPORTANT:
            # Exact issue/evidence generated
            # by the scanner.
            vuln_data[
                "issue"
            ] = issues.get(
                key,
                ""
            )

            found_vulns.append(
                vuln_data
            )

        # =================================================
        # TEMPLATE CONTEXT
        # =================================================

        context = {

            "url":
                url,

            "risk_label":
                risk_info[
                    "label"
                ],

            "risk_score":
                security_score,

            "score_hex":
                risk_info[
                    "hex"
                ],

            "risk_text_color":
                risk_info[
                    "text"
                ],

            "confidence":
                confidence,

            "total_issues":
                len(
                    found_vulns
                ),

            "found_vulns":
                found_vulns,

            "raw_flags":
                vulnerability_details,

            "issues":
                issues,
        }

        return render(
            request,
            "websites/report.html",
            context
        )

    # =====================================================
    # FAILED / INCOMPLETE SCAN
    # =====================================================

    return render(
        request,
        "websites/report.html",
        {
            "url":
                "Error",

            "risk_label":
                "SCAN FAILED",

            "risk_score":
                0,

            "score_hex":
                "#333333",

            "risk_text_color":
                "text-slate-500",

            "confidence":
                0,

            "total_issues":
                0,

            "found_vulns":
                [],

            "raw_flags":
                {},

            "issues":
                {},
        }
    )

# ============================================================
# HISTORY
# ============================================================

def history_view(request):

    if "user_id" not in request.session:
        return redirect("login")

    # Our History UI is inside the Profile page
    return redirect(
        f"{reverse('profile')}#history-section"
    )


# ============================================================
# REPORTS
# ============================================================

def reports_view(request):

    if "user_id" not in request.session:
        return redirect("login")

    user_id = request.session.get(
        "user_id"
    )

    scan_objects = (
        Scan.objects
        .select_related("website")
        .filter(
            website__user_id=user_id
        )
        .order_by("-scan_date")
    )

    scans = []

    for scan in scan_objects:

        findings = (
            Vulnerability.objects
            .filter(
                scan=scan
            )
            .count()
        )

        confidence = recompute_saved_confidence(
            scan
        )

        display_score = max(
            0,
            100 - (findings * 8)
        )

        scans.append({

            "created_at":
                scan.scan_date,

            "target_url":
                scan.website.website_url,

            "risk_level":
                scan.risk_level
                or "Unknown",

            "confidence":
                confidence,

            # IMPORTANT:
            # use scan.pk with current models
            "task_id":
                scan.pk,

            "scan_id":
                scan.pk,

            "security_score":
                display_score,

            "findings":
                findings,
        })

    return render(
        request,
        "reports/reports.html",
        {
            "scans": scans
        }
    )