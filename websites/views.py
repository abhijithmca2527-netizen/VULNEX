from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from celery.result import AsyncResult
from django.urls import reverse

from .tasks import run_vulnex_scan
from .utils import VULNERABILITY_DICT
from .ml_engine import VulnexAIEngine
from .models import Scan, Vulnerability


# ============================================================
# DASHBOARD
# ============================================================

def dashboard_view(request):

    return render(
        request,
        "dashboard.html"
    )


# ============================================================
# START SCAN
# ============================================================

def start_scan_view(request):

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


# ============================================================
# CHECK CELERY TASK STATUS
# ============================================================

def check_scan_status(
    request,
    task_id
):

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


# ============================================================
# FIXED FEATURE ORDER
# ============================================================

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


# ============================================================
# REBUILD SAVED VECTOR
# ============================================================

def rebuild_saved_scan_vector(scan):

    stored_names = {

        str(name)
        .strip()
        .lower()

        for name
        in Vulnerability.objects.filter(
            scan=scan
        ).values_list(
            "vulnerability_name",
            flat=True
        )
    }


    vector = []


    for key in FEATURE_KEYS:

        info = VULNERABILITY_DICT.get(
            key,
            {}
        )

        expected_name = (
            str(
                info.get(
                    "name",
                    ""
                )
            )
            .strip()
            .lower()
        )


        vector.append(

            1
            if expected_name
            in stored_names
            else 0

        )


    return vector


# ============================================================
# SAVED SCAN CONFIDENCE
# ============================================================

def recompute_saved_confidence(scan):

    try:

        risk_level = (
            str(
                scan.risk_level
                or ""
            )
            .strip()
            .upper()
        )


        # Clean scans are handled by Ollama in the
        # current VulnEx architecture.
        #
        # Do not send an all-zero vector back through
        # Random Forest just to calculate confidence.

        if risk_level == "CLEAN":

            return 0


        # Semantic Zero-Day findings also belong
        # to the Ollama path.

        semantic_exists = (
            Vulnerability.objects.filter(
                scan=scan,
                vulnerability_name=(
                    "Semantic Zero-Day Threat"
                )
            ).exists()
        )


        if semantic_exists:

            return 0


        vector = rebuild_saved_scan_vector(
            scan
        )


        result = (
            VulnexAIEngine()
            .predict_risk(
                vector
            )
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
# DATABASE / SAVED REPORT CONTEXT
# ============================================================

def build_database_report_context(scan):

    vulnerabilities = (
        Vulnerability.objects
        .filter(
            scan=scan
        )
        .order_by(
            "vulnerability_id"
        )
    )


    found_vulns = []

    raw_flags = {}

    semantic_ollama_finding = False


    # ========================================================
    # LOAD SAVED VULNERABILITIES
    # ========================================================

    for vulnerability in vulnerabilities:

        matched_key = None

        vuln_data = None


        # ----------------------------------------------------
        # OLLAMA SEMANTIC FINDING
        # ----------------------------------------------------

        if (
            vulnerability.vulnerability_name
            == "Semantic Zero-Day Threat"
        ):

            matched_key = (
                "semantic_zero_day"
            )

            vuln_data = {

                "name":
                    vulnerability.vulnerability_name,

                "description":
                    vulnerability.description,

                "fix":
                    (
                        "Investigate anomalous "
                        "configurations and rotate "
                        "exposed secrets immediately."
                    ),
            }

            semantic_ollama_finding = True


        # ----------------------------------------------------
        # STANDARD VULNEX FINDING
        # ----------------------------------------------------

        else:

            for (
                key,
                data
            ) in VULNERABILITY_DICT.items():

                expected_name = (
                    str(
                        data.get(
                            "name",
                            ""
                        )
                    )
                    .strip()
                    .lower()
                )

                stored_name = (
                    str(
                        vulnerability
                        .vulnerability_name
                    )
                    .strip()
                    .lower()
                )


                if (
                    expected_name
                    == stored_name
                ):

                    matched_key = key

                    vuln_data = (
                        data.copy()
                    )

                    break


        # ----------------------------------------------------
        # UNKNOWN / HISTORICAL FINDING
        # ----------------------------------------------------

        if vuln_data is None:

            vuln_data = {

                "name":
                    vulnerability
                    .vulnerability_name,

                "description":
                    (
                        vulnerability.description
                        or
                        (
                            "Security weakness detected "
                            "during passive analysis."
                        )
                    ),

                "fix":
                    (
                        "Review and apply the "
                        "recommended security "
                        "configuration."
                    ),
            }


        vuln_data[
            "issue"
        ] = (

            vulnerability.issue

            or

            (
                "Issue detected during "
                "passive security analysis."
            )
        )


        if matched_key:

            vuln_data[
                "key"
            ] = matched_key

            raw_flags[
                matched_key
            ] = True


        found_vulns.append(
            vuln_data
        )


    # ========================================================
    # RISK
    # ========================================================

    risk_level = (
        str(
            scan.risk_level
            or "UNKNOWN"
        )
        .strip()
        .upper()
    )


    # ========================================================
    # DETERMINE AI ENGINE
    #
    # Current architecture:
    #
    # non-zero vector -> Random Forest
    # zero vector     -> Ollama
    #
    # A CLEAN result therefore comes from the Ollama path.
    # ========================================================

    is_ollama = (

        risk_level == "CLEAN"

        or

        semantic_ollama_finding

    )


    if is_ollama:

        engine_label = (
            "Ollama LLM (Llama 3)"
        )

    else:

        engine_label = (
            "Random Forest Classifier"
        )


    # ========================================================
    # UI RISK MAPPING
    # ========================================================

    ui_mapping = {

        "CLEAN": {
            "label": "CLEAN",
            "hex": "#4ADE80",
            "text": "text-green-400",
        },

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
        ui_mapping[
            "UNKNOWN"
        ]
    )


    security_score = (

        scan.security_score

        if scan.security_score
        is not None

        else 100

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
            recompute_saved_confidence(
                scan
            ),

        "total_issues":
            len(
                found_vulns
            ),

        "found_vulns":
            found_vulns,

        "raw_flags":
            raw_flags,

        "issues": {

            item.get(
                "key",
                f"finding_{index}"
            ):
            item.get(
                "issue",
                ""
            )

            for (
                index,
                item
            )
            in enumerate(
                found_vulns
            )
        },

        "scan_id":
            scan.pk,

        "created_at":
            scan.scan_date,

        "is_ollama":
            is_ollama,

        "engine_label":
            engine_label,
    }


# ============================================================
# SCAN REPORT
# ============================================================

def scan_report(
    request,
    task_id
):

    if (
        "user_id"
        not in request.session
    ):

        return redirect(
            "login"
        )


    user_id = (
        request.session.get(
            "user_id"
        )
    )


    identifier = (
        str(
            task_id
        )
        .strip()
    )


    # ========================================================
    # SAVED DATABASE REPORT
    # ========================================================

    if identifier.isdigit():

        try:

            scan = (
                Scan.objects
                .select_related(
                    "website"
                )
                .get(
                    pk=int(
                        identifier
                    ),
                    website__user_id=(
                        user_id
                    )
                )
            )


            return render(
                request,
                "websites/report.html",
                build_database_report_context(
                    scan
                )
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

                    "total_issues":
                        0,

                    "is_ollama":
                        False,

                    "engine_label":
                        "Unavailable",
                }
            )


    # ========================================================
    # LIVE CELERY RESULT
    # ========================================================

    task_result = AsyncResult(
        identifier
    )


    if (
        task_result.state
        == "SUCCESS"
    ):

        scan_data = (

            task_result.result

            if isinstance(
                task_result.result,
                dict
            )

            else {}

        )


        url = scan_data.get(
            "url",
            "Target Domain"
        )


        ai_prediction = (

            scan_data.get(
                "ai_prediction",
                {}
            )

            if isinstance(
                scan_data.get(
                    "ai_prediction"
                ),
                dict
            )

            else {}

        )


        # ====================================================
        # ENGINE
        # ====================================================

        source_engine = (
            scan_data.get(
                "source"
            )
            or
            ai_prediction.get(
                "source"
            )
            or
            "Random Forest Classifier"
        )


        is_ollama = (
            source_engine
            == "Ollama LLM (Llama 3)"
        )


        if is_ollama:

            engine_label = (
                "Ollama LLM (Llama 3)"
            )

        else:

            engine_label = (
                "Random Forest Classifier"
            )


        # ====================================================
        # RISK
        # ====================================================

        risk_raw = (
            scan_data.get(
                "risk_category"
            )
        )


        if risk_raw is None:

            risk_raw = (
                ai_prediction.get(
                    "risk_level",
                    "Unknown"
                )
            )


        if isinstance(
            risk_raw,
            int
        ):

            risk_level_str = {

                0: "LOW",

                1: "MEDIUM",

                2: "HIGH",

                3: "CRITICAL",

            }.get(
                risk_raw,
                "UNKNOWN"
            )

        else:

            risk_level_str = (
                str(
                    risk_raw
                )
                .strip()
                .upper()
            )


        # ====================================================
        # UI MAPPING
        # ====================================================

        ui_mapping = {

            "CLEAN": {
                "label": "CLEAN",
                "score": 100,
                "hex": "#4ADE80",
                "text": "text-green-400",
            },

            "LOW": {
                "label": "LOW RISK",
                "score": 95,
                "hex": "#4ADE80",
                "text": "text-green-400",
            },

            "MEDIUM": {
                "label": "MEDIUM RISK",
                "score": 75,
                "hex": "#FDE047",
                "text": "text-yellow-300",
            },

            "HIGH": {
                "label": "HIGH RISK",
                "score": 40,
                "hex": "#FB923C",
                "text": "text-orange-400",
            },

            "CRITICAL": {
                "label": "CRITICAL RISK",
                "score": 15,
                "hex": "#F87171",
                "text": "text-red-400",
            },

            "UNKNOWN": {
                "label": "UNKNOWN RISK",
                "score": 0,
                "hex": "#64748B",
                "text": "text-slate-400",
            },
        }


        risk_info = ui_mapping.get(
            risk_level_str,
            ui_mapping[
                "UNKNOWN"
            ]
        )


        # ====================================================
        # SECURITY SCORE
        # ====================================================

        security_score = (
            scan_data.get(
                "security_score"
            )
        )


        if security_score is None:

            security_score = (
                ai_prediction.get(
                    "security_score"
                )
            )


        if security_score is None:

            security_score = (
                risk_info[
                    "score"
                ]
            )


        # ====================================================
        # CONFIDENCE
        # ====================================================

        confidence_value = (
            scan_data.get(
                "confidence"
            )
        )


        if confidence_value is None:

            confidence_value = (
                ai_prediction.get(
                    "confidence",
                    0
                )
            )


        try:

            confidence = round(
                float(
                    confidence_value
                ),
                2
            )

        except (
            TypeError,
            ValueError
        ):

            confidence = 0


        # ====================================================
        # VULNERABILITY DATA
        # ====================================================

        vulnerability_details = (

            scan_data.get(
                "vulnerability_details",
                {}
            )

            if isinstance(
                scan_data.get(
                    "vulnerability_details"
                ),
                dict
            )

            else {}

        )


        issues = (

            scan_data.get(
                "issues",
                {}
            )

            if isinstance(
                scan_data.get(
                    "issues"
                ),
                dict
            )

            else {}

        )


        # If task returned only vector,
        # rebuild the detail dictionary.

        if (
            not vulnerability_details
            and
            "vector"
            in scan_data
        ):

            vector = (
                scan_data.get(
                    "vector",
                    []
                )
            )

            vulnerability_details = {

                FEATURE_KEYS[index]:
                    bool(
                        vector[index]
                    )

                for index
                in range(
                    min(
                        len(
                            FEATURE_KEYS
                        ),
                        len(
                            vector
                        )
                    )
                )
            }


        # ====================================================
        # BUILD FINDINGS
        # ====================================================

        found_vulns = []


        for (
            key,
            is_vulnerable
        ) in vulnerability_details.items():

            if not is_vulnerable:

                continue


            # -----------------------------------------------
            # OLLAMA SEMANTIC FINDING
            # -----------------------------------------------

            if (
                key
                == "semantic_zero_day"
            ):

                found_vulns.append({

                    "key":
                        key,

                    "name":
                        (
                            "Semantic "
                            "Zero-Day Threat"
                        ),

                    "issue":
                        issues.get(
                            key,
                            ""
                        ),

                    "description":
                        (
                            "Novel vulnerability "
                            "detected via Deep "
                            "LLM Inspection."
                        ),

                    "fix":
                        (
                            "Investigate anomalous "
                            "configurations and rotate "
                            "exposed secrets."
                        ),
                })

                continue


            # -----------------------------------------------
            # STANDARD VULNERABILITY
            # -----------------------------------------------

            if (
                key
                not in VULNERABILITY_DICT
            ):

                continue


            vuln_data = (
                VULNERABILITY_DICT[
                    key
                ].copy()
            )


            vuln_data[
                "key"
            ] = key


            vuln_data[
                "issue"
            ] = issues.get(
                key,
                ""
            )


            found_vulns.append(
                vuln_data
            )


        # ====================================================
        # TEMPLATE CONTEXT
        # ====================================================

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

            "is_ollama":
                is_ollama,

            "engine_label":
                engine_label,
        }


        return render(
            request,
            "websites/report.html",
            context
        )


    # ========================================================
    # SCAN FAILURE
    # ========================================================

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

            "total_issues":
                0,

            "is_ollama":
                False,

            "engine_label":
                "Unavailable",
        }
    )


# ============================================================
# HISTORY
# ============================================================

def history_view(request):

    if (
        "user_id"
        not in request.session
    ):

        return redirect(
            "login"
        )


    return redirect(
        f"{reverse('profile')}"
        "#history-section"
    )


# ============================================================
# REPORT LIST
# ============================================================

def reports_view(request):

    if (
        "user_id"
        not in request.session
    ):

        return redirect(
            "login"
        )


    user_id = (
        request.session.get(
            "user_id"
        )
    )


    scan_objects = (

        Scan.objects
        .select_related(
            "website"
        )
        .filter(
            website__user_id=(
                user_id
            )
        )
        .order_by(
            "-scan_date"
        )
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


        security_score = (

            scan.security_score

            if scan.security_score
            is not None

            else 100

        )


        scans.append({

            "created_at":
                scan.scan_date,

            "target_url":
                scan.website.website_url,

            "risk_level":
                (
                    scan.risk_level
                    or "Unknown"
                ),

            "confidence":
                recompute_saved_confidence(
                    scan
                ),

            "task_id":
                scan.pk,

            "scan_id":
                scan.pk,

            "security_score":
                security_score,

            "findings":
                findings,
        })


    return render(
        request,
        "reports/reports.html",
        {
            "scans":
                scans
        }
    )


# ============================================================
# CONTROLLED OLLAMA TEST TARGET
# ============================================================

def zero_day_test_target(request):

    """
    Controlled local target with secure baseline headers
    and simulated semantic disclosure.
    """

    response = HttpResponse(
        "Vulnex Tier 2 Honeypot Target"
    )


    response[
        "Strict-Transport-Security"
    ] = (
        "max-age=31536000; "
        "includeSubDomains"
    )


    response[
        "X-Frame-Options"
    ] = "DENY"


    response[
        "X-Content-Type-Options"
    ] = "nosniff"


    response[
        "Content-Security-Policy"
    ] = "default-src 'self'"


    response[
        "Server"
    ] = "VulnexSecureGateway"


    response[
        "Set-Cookie"
    ] = (
        "session=trusted; "
        "HttpOnly; Secure"
    )


    response[
        "X-Backend-Database-IP"
    ] = "10.240.5.112"


    response[
        "X-Debug-API-Token"
    ] = (
        "vulnex_admin_secret_9942"
    )


    return response