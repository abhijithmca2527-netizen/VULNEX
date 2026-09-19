from urllib.parse import urlparse

from celery import shared_task
from django.db import transaction

from .feature_extractor import VulnexFeatureExtractor
from .ml_engine import VulnexAIEngine
from .models import (
    Website,
    Scan,
    Vulnerability,
    Report,
    SandboxThreat,
)
from .utils import VULNERABILITY_DICT
from users.models import User


@shared_task
def run_vulnex_scan(target_url, user_id=None):
    """
    Run the VULNEX scan.

    Keeps Jowin's Random Forest + Isolation Forest anomaly flow,
    but saves normal scans into the existing Supabase tables:
    WEBSITES -> SCANS -> VULNERABILITIES -> REPORTS.

    It does NOT use the obsolete ScanResult/websites_scanresult table.
    """

    print(f"\n[VULNEX] Scanning: {target_url}")

    # =====================================================
    # 1. FEATURE EXTRACTION
    # =====================================================

    extractor = VulnexFeatureExtractor(timeout=5)

    extracted_data = extractor.extract_features(
        target_url
    )

    binary_vector = extracted_data.get(
        "feature_vector",
        []
    )

    vulnerability_details = extracted_data.get(
        "details",
        {}
    )

    # Exact site-specific evidence for the Issue column.
    issues = extracted_data.get(
        "issues",
        {}
    )

    if not isinstance(vulnerability_details, dict):
        vulnerability_details = {}

    if not isinstance(issues, dict):
        issues = {}

    if len(binary_vector) != 12:
        raise ValueError(
            f"Expected 12 vulnerability features, got {len(binary_vector)}."
        )

    # =====================================================
    # 2. RANDOM FOREST + ISOLATION FOREST
    # =====================================================

    ai_engine = VulnexAIEngine()

    ai_results = ai_engine.predict_risk(
        binary_vector
    )

    risk_level = ai_results.get(
        "risk_level",
        "Unknown"
    )

    # Random Forest confidence stays an ML value.
    confidence = ai_results.get(
        "confidence",
        0
    )

    # Health Score is based on the number of detected findings.
    # This matches the Scan History logic we built earlier:
    # 0 findings = 100, 1 = 92, 4 = 68, etc.
    findings_count = sum(
        1
        for value in binary_vector
        if value == 1
    )

    security_score = max(
        0,
        100 - (findings_count * 8)
    )

    is_anomaly = ai_results.get(
        "is_anomaly",
        False
    )

    print(
        f"[VULNEX] Vector: {binary_vector}"
    )

    print(
        f"[VULNEX] Risk: {risk_level} | "
        f"Security Score: {security_score}/100"
    )

    # =====================================================
    # 3. ANOMALY / QUARANTINE FLOW
    # =====================================================

    if is_anomaly:

        print(
            "[⚠ ANOMALY DETECTED] "
            "Sending to Quarantine Sandbox..."
        )

        SandboxThreat.objects.create(
            target_url=target_url,
            feature_vector=str(binary_vector),
            rf_predicted_risk=risk_level
        )

        # IMPORTANT:
        # Keep the anomaly in the sandbox, but ALSO save the
        # completed user scan into the normal Supabase history.
        # This ensures every completed scan appears in
        # History and Reports.
        print(
            "[VULNEX] Anomaly quarantined. "
            "Also saving completed scan to Supabase history..."
        )

    else:

        print(
            "[✅ NORMAL PATTERN] "
            "Saving to Supabase scan history..."
        )

    # =====================================================
    # 4. SAVE EVERY COMPLETED SCAN -> REAL SUPABASE HISTORY
    # =====================================================

    if not user_id:
        raise ValueError(
            "A logged-in user_id is required to save the scan."
        )

    try:
        user = User.objects.get(
            pk=user_id
        )
    except User.DoesNotExist as exc:
        raise ValueError(
            f"Logged-in user {user_id} was not found."
        ) from exc

    # Normalize URL before saving.
    normalized_url = target_url.strip()

    if not normalized_url.startswith(
        ("http://", "https://")
    ):
        normalized_url = (
            "https://" + normalized_url
        )

    parsed_url = urlparse(
        normalized_url
    )

    website_name = (
        parsed_url.hostname
        or normalized_url
    )

    # SCANS.security_score is an integer in the existing
    # Supabase schema, so store a rounded integer there.
    try:
        db_security_score = int(
            round(float(security_score))
        )
    except (TypeError, ValueError):
        db_security_score = 0

    saved_vulnerabilities = []

    # =====================================================
    # 5. SAVE EXISTING SUPABASE TABLES
    # =====================================================

    with transaction.atomic():

        # -------------------------------------------------
        # WEBSITES
        # -------------------------------------------------

        website, _ = Website.objects.get_or_create(
            user=user,
            website_url=normalized_url,
            defaults={
                "website_name": website_name
            }
        )

        if not website.website_name:
            website.website_name = website_name
            website.save(
                update_fields=[
                    "website_name"
                ]
            )

        # -------------------------------------------------
        # SCANS
        # -------------------------------------------------

        scan = Scan.objects.create(
            website=website,
            security_score=db_security_score,
            risk_level=risk_level
        )

        # -------------------------------------------------
        # VULNERABILITIES + ISSUE EVIDENCE
        # -------------------------------------------------

        for (
            vuln_key,
            is_vulnerable
        ) in vulnerability_details.items():

            if not is_vulnerable:
                continue

            vuln_info = VULNERABILITY_DICT.get(
                vuln_key,
                {}
            )

            if isinstance(vuln_info, dict):
                vulnerability_name = vuln_info.get(
                    "name"
                )
                description = vuln_info.get(
                    "description"
                )
            else:
                vulnerability_name = None
                description = None

            vulnerability_name = (
                vulnerability_name
                or vuln_key.replace(
                    "_",
                    " "
                ).title()
            )

            description = (
                description
                or
                "Detected by VulnEx passive security analysis."
            )

            issue = issues.get(
                vuln_key,
                "Issue detected during passive security analysis."
            )

            vulnerability = (
                Vulnerability.objects.create(
                    scan=scan,
                    vulnerability_name=vulnerability_name,
                    issue=issue,
                    description=description
                )
            )

            saved_vulnerabilities.append(
                vulnerability
            )

        # -------------------------------------------------
        # REPORTS
        # -------------------------------------------------

        report = Report.objects.create(
            scan=scan,
            report_file=""
        )

    # =====================================================
    # 6. TERMINAL OUTPUT
    # =====================================================

    print(
        f"[VULNEX] User PK: {user.pk}"
    )

    print(
        f"[VULNEX] Website PK: {website.pk}"
    )

    print(
        f"[VULNEX] Scan PK: {scan.pk}"
    )

    print(
        f"[VULNEX] Findings: "
        f"{len(saved_vulnerabilities)}"
    )

    print(
        f"[VULNEX] Issues: {issues}"
    )

    print(
        "[VULNEX] Scan Complete!\n"
    )

    # =====================================================
    # 7. DATA RETURNED TO report.html
    # =====================================================

    return {
        "url": normalized_url,
        "vector": binary_vector,
        "vulnerability_details": vulnerability_details,
        "issues": issues,
        "risk_category": risk_level,
        "security_score": db_security_score,
        "confidence": confidence,
        "is_anomaly": bool(is_anomaly),
        "scan_id": scan.pk,
        "website_id": website.pk,
        "report_id": report.pk,
        "ai_prediction": ai_results,
    }
