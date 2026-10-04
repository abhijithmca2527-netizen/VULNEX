import json
import requests

from urllib.parse import urlparse

from celery import shared_task
from django.db import transaction

from .feature_extractor import VulnexFeatureExtractor
from .ml_engine import VulnexAIEngine

from .models import (
    Website,
    Scan,
    Vulnerability,
    Report
)

from .utils import VULNERABILITY_DICT

from users.models import User




# ============================================================
# VULNEX WEIGHTED SECURITY SCORE
# ============================================================

PENALTY_WEIGHTS = {
    0: 20,   # Missing HSTS
    1: 15,   # Missing X-Frame-Options
    2: 5,    # Missing X-Content-Type-Options
    3: 25,   # Missing Content-Security-Policy
    4: 5,    # Exposed Server Version
    5: 5,    # Exposed X-Powered-By
    6: 15,   # Weak / Invalid SSL/TLS
    7: 10,   # Exposed Directory Listing
    8: 5,    # Cookie Missing HttpOnly
    9: 5,    # Cookie Missing Secure
    10: 10,  # Insecure CORS Wildcard
    11: 5,   # Outdated CMS / Generator
}


def calculate_security_score(binary_vector):

    deductions = 0

    for index, bit in enumerate(binary_vector):

        if int(bit) == 1:

            deductions += PENALTY_WEIGHTS.get(
                index,
                0
            )

    return max(
        0,
        100 - deductions
    )

# ============================================================
# OLLAMA DEEP ANALYSIS
#
# Ollama is used ONLY when all 12 standard vulnerability
# features are zero.
# ============================================================

def analyze_with_ollama(
    target_url,
    raw_headers
):

    print(
        "[VULNEX] Zero vulnerability vector detected."
    )

    print(
        "[VULNEX] Routing scan to Ollama..."
    )

    prompt = f"""
You are the secondary security analysis engine of VulnEx.

The normal VulnEx passive vulnerability checks produced a
12-bit vector containing only zeros.

Target URL:
{target_url}

HTTP response headers:
{json.dumps(raw_headers, default=str)}

Analyze ONLY the supplied HTTP response headers.

Look for security concerns such as:

- accidentally exposed secrets
- API keys
- tokens
- credentials
- debug information
- internal configuration information
- unusual sensitive headers
- other security exposure not represented by the standard checks

Do not invent vulnerabilities.

Return ONLY valid JSON using exactly this format:

{{
    "novel_threat_found": false,
    "threat_score": 0,
    "confidence": 0,
    "summary": "Brief explanation"
}}

Rules:

1. novel_threat_found must be true or false.
2. threat_score must be between 0 and 100.
3. confidence must be between 0 and 100.
4. If no additional threat exists, novel_threat_found must be false.
5. Do not return markdown.
"""

    try:

        response = requests.post(
            "http://127.0.0.1:11434/api/chat",
            json={
                "model": "llama3",
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "stream": False,
                "format": "json"
            },
            timeout=35
        )

        response.raise_for_status()


        # ====================================================
        # GET OLLAMA RESPONSE
        # ====================================================

        raw_content = (
            response
            .json()
            .get(
                "message",
                {}
            )
            .get(
                "content",
                ""
            )
        )

        clean_json = raw_content.strip()


        # Remove markdown fences if model returns them
        if clean_json.startswith(
            "```json"
        ):

            clean_json = (
                clean_json[7:]
            )

        elif clean_json.startswith(
            "```"
        ):

            clean_json = (
                clean_json[3:]
            )


        if clean_json.endswith(
            "```"
        ):

            clean_json = (
                clean_json[:-3]
            )


        llm_data = json.loads(
            clean_json.strip()
        )


        # ====================================================
        # NOVEL THREAT
        # ====================================================

        novel_threat_found = bool(
            llm_data.get(
                "novel_threat_found",
                False
            )
        )


        # ====================================================
        # THREAT SCORE
        # ====================================================

        try:

            threat_score = int(
                round(
                    float(
                        llm_data.get(
                            "threat_score",
                            0
                        )
                    )
                )
            )

        except (
            TypeError,
            ValueError
        ):

            threat_score = 0


        threat_score = max(
            0,
            min(
                100,
                threat_score
            )
        )


        # ====================================================
        # CONFIDENCE
        # ====================================================

        try:

            confidence = float(
                llm_data.get(
                    "confidence",
                    0
                )
            )

        except (
            TypeError,
            ValueError
        ):

            confidence = 0


        confidence = max(
            0,
            min(
                100,
                confidence
            )
        )


        summary = str(
            llm_data.get(
                "summary",
                "Ollama analysis completed."
            )
        ).strip()


        # ====================================================
        # CONTROLLED VULNEX TEST SECRET CHECK
        # ====================================================

        header_text = json.dumps(
            raw_headers,
            default=str
        ).lower()


        if (
            "vulnex_admin_secret"
            in header_text
        ):

            novel_threat_found = True

            threat_score = max(
                threat_score,
                85
            )

            if not summary:

                summary = (
                    "Sensitive VulnEx test "
                    "information was exposed "
                    "through an HTTP header."
                )


        # ====================================================
        # NO EXTRA THREAT FOUND
        # ====================================================

        if not novel_threat_found:

            print(
                "[VULNEX] Ollama found no "
                "additional semantic threat."
            )

            return {
                "risk_level": "Clean",
                "security_score": 100,
                "confidence": confidence,
                "novel_threat_found": False,
                "summary": summary,
                "source": "Ollama LLM (Llama 3)"
            }


        # ====================================================
        # MAP OLLAMA THREAT SCORE TO RISK
        # ====================================================

        if threat_score >= 80:

            risk_level = "Critical"

        elif threat_score >= 60:

            risk_level = "High"

        elif threat_score >= 40:

            risk_level = "Medium"

        else:

            risk_level = "Low"


        security_score = max(
            0,
            100 - threat_score
        )


        print(
            "[VULNEX] Ollama detected an "
            "additional semantic security threat."
        )


        return {
            "risk_level": risk_level,
            "security_score": security_score,
            "confidence": confidence,
            "novel_threat_found": True,
            "summary": summary,
            "source": "Ollama LLM (Llama 3)"
        }


    except Exception as exc:

        print(
            "[VULNEX] Ollama analysis failed: "
            f"{exc}"
        )

        # Standard 12 checks found no issue.
        # We still save the scan instead of crashing.

        return {
            "risk_level": "Clean",
            "security_score": 100,
            "confidence": 0,
            "novel_threat_found": False,
            "summary": (
                "Ollama was unavailable. "
                "No standard vulnerability "
                "indicators were detected."
            ),
            "source": (
                "Passive checks "
                "(Ollama unavailable)"
            )
        }


# ============================================================
# MAIN VULNEX CELERY SCAN TASK
# ============================================================

@shared_task
def run_vulnex_scan(
    target_url,
    user_id=None
):

    print(
        f"\n[VULNEX] Scanning: "
        f"{target_url}"
    )


    # ========================================================
    # 1. FEATURE EXTRACTION
    # ========================================================

    extractor = VulnexFeatureExtractor(
        timeout=5
    )


    extracted_data = (
        extractor.extract_features(
            target_url
        )
    )


    binary_vector = (
        extracted_data.get(
            "feature_vector",
            []
        )
    )


    vulnerability_details = (
        extracted_data.get(
            "details",
            {}
        )
    )


    issues = (
        extracted_data.get(
            "issues",
            {}
        )
    )


    raw_data = (
        extracted_data.get(
            "raw_data",
            {}
        )
    )


    # ========================================================
    # VALIDATE EXTRACTED DATA
    # ========================================================

    if not isinstance(
        vulnerability_details,
        dict
    ):

        vulnerability_details = {}


    if not isinstance(
        issues,
        dict
    ):

        issues = {}


    if not isinstance(
        raw_data,
        dict
    ):

        raw_data = {}


    raw_headers = raw_data.get(
        "headers",
        {}
    )


    if not isinstance(
        raw_headers,
        dict
    ):

        raw_headers = {}


    if len(binary_vector) != 12:

        raise ValueError(
            "Expected 12 vulnerability "
            f"features, got "
            f"{len(binary_vector)}."
        )


    # ========================================================
    # COUNT STANDARD FINDINGS
    # ========================================================

    findings_count = sum(
        1
        for value in binary_vector
        if value == 1
    )


    print(
        f"[VULNEX] Vector: "
        f"{binary_vector}"
    )


    print(
        f"[VULNEX] Standard findings: "
        f"{findings_count}"
    )


    # ========================================================
    # 2. AI ROUTING
    #
    # NON-ZERO VECTOR → RANDOM FOREST
    # ZERO VECTOR     → OLLAMA
    # ========================================================

    novel_threat_found = False


    # ========================================================
    # RANDOM FOREST
    # ========================================================

    if findings_count > 0:

        print(
            "[VULNEX] Standard vulnerability "
            "indicators detected."
        )

        print(
            "[VULNEX] Routing scan to "
            "Random Forest..."
        )


        ai_engine = VulnexAIEngine()


        ai_results = (
            ai_engine.predict_risk(
                binary_vector
            )
        )


        risk_level = (
            ai_results.get(
                "risk_level",
                "Unknown"
            )
        )


        confidence = (
            ai_results.get(
                "confidence",
                0
            )
        )


        # ----------------------------------------------------
        # VulnEx security score
        # ----------------------------------------------------

        security_score = (
    calculate_security_score(
        binary_vector
    )
)


        source_engine = (
            "Random Forest Classifier"
        )


        # Keep score returned by main VulnEx logic
        ai_results[
            "security_score"
        ] = security_score


    # ========================================================
    # OLLAMA
    # ========================================================

    else:

        ollama_results = (
            analyze_with_ollama(
                target_url,
                raw_headers
            )
        )


        risk_level = (
            ollama_results.get(
                "risk_level",
                "Clean"
            )
        )


        security_score = (
            ollama_results.get(
                "security_score",
                100
            )
        )


        confidence = (
            ollama_results.get(
                "confidence",
                0
            )
        )


        novel_threat_found = (
            ollama_results.get(
                "novel_threat_found",
                False
            )
        )


        source_engine = (
            ollama_results.get(
                "source",
                "Ollama LLM (Llama 3)"
            )
        )


        ai_results = ollama_results


        # ----------------------------------------------------
        # If Ollama found an extra issue,
        # save it as a normal vulnerability record.
        # ----------------------------------------------------

        if novel_threat_found:

            vulnerability_details[
                "semantic_zero_day"
            ] = True


            issues[
                "semantic_zero_day"
            ] = (
                ollama_results.get(
                    "summary",
                    (
                        "Additional semantic "
                        "security concern detected "
                        "by Ollama."
                    )
                )
            )


    # ========================================================
    # AI OUTPUT
    # ========================================================

    print(
        f"[VULNEX] AI Engine: "
        f"{source_engine}"
    )


    print(
        f"[VULNEX] Risk: "
        f"{risk_level}"
    )


    print(
        f"[VULNEX] Security Score: "
        f"{security_score}/100"
    )


    # ========================================================
    # 3. LOGGED-IN USER
    # ========================================================

    if not user_id:

        raise ValueError(
            "A logged-in user_id is required "
            "to save the scan."
        )


    try:

        user = User.objects.get(
            pk=user_id,
            role="user"
        )


    except User.DoesNotExist as exc:

        raise ValueError(
            f"Logged-in user "
            f"{user_id} was not found."
        ) from exc


    # ========================================================
    # 4. NORMALIZE URL
    # ========================================================

    normalized_url = (
        target_url.strip()
    )


    if not normalized_url.startswith(
        (
            "http://",
            "https://"
        )
    ):

        normalized_url = (
            "https://"
            + normalized_url
        )


    parsed_url = urlparse(
        normalized_url
    )


    website_name = (
        parsed_url.hostname
        or normalized_url
    )


    # ========================================================
    # SECURITY SCORE FOR DATABASE
    # ========================================================

    try:

        db_security_score = int(
            round(
                float(
                    security_score
                )
            )
        )


    except (
        TypeError,
        ValueError
    ):

        db_security_score = 0


    db_security_score = max(
        0,
        min(
            100,
            db_security_score
        )
    )


    saved_vulnerabilities = []


    # ========================================================
    # 5. SAVE EVERYTHING TO SUPABASE
    # ========================================================

    print(
        "[VULNEX] Saving scan to "
        "Supabase..."
    )


    with transaction.atomic():


        # ====================================================
        # WEBSITE
        # ====================================================

        website, _ = (
            Website.objects.get_or_create(
                user=user,
                website_url=normalized_url,
                defaults={
                    "website_name":
                    website_name
                }
            )
        )


        if not website.website_name:

            website.website_name = (
                website_name
            )

            website.save(
                update_fields=[
                    "website_name"
                ]
            )


        # ====================================================
        # SCAN
        # ====================================================

        scan = Scan.objects.create(
            website=website,
            user=user,
            security_score=(
                db_security_score
            ),
            risk_level=risk_level
        )


        # ====================================================
        # VULNERABILITY RECORDS
        # ====================================================

        for (
            vuln_key,
            is_vulnerable
        ) in (
            vulnerability_details.items()
        ):


            if not is_vulnerable:

                continue


            # ================================================
            # OLLAMA SEMANTIC FINDING
            # ================================================

            if (
                vuln_key
                == "semantic_zero_day"
            ):

                vulnerability_name = (
                    "Semantic Security Threat"
                )


                description = (
                    "Additional security concern "
                    "detected through Ollama "
                    "semantic header inspection."
                )


            # ================================================
            # STANDARD VULNEX FINDING
            # ================================================

            else:

                vuln_info = (
                    VULNERABILITY_DICT.get(
                        vuln_key,
                        {}
                    )
                )


                if isinstance(
                    vuln_info,
                    dict
                ):

                    vulnerability_name = (
                        vuln_info.get(
                            "name"
                        )
                    )


                    description = (
                        vuln_info.get(
                            "description"
                        )
                    )


                else:

                    vulnerability_name = None
                    description = None


                vulnerability_name = (
                    vulnerability_name
                    or
                    vuln_key
                    .replace(
                        "_",
                        " "
                    )
                    .title()
                )


                description = (
                    description
                    or
                    (
                        "Detected by VulnEx "
                        "passive security analysis."
                    )
                )


            issue = issues.get(
                vuln_key,
                (
                    "Issue detected during "
                    "passive security analysis."
                )
            )


            vulnerability = (
                Vulnerability.objects.create(
                    scan=scan,
                    vulnerability_name=(
                        vulnerability_name
                    ),
                    issue=issue,
                    description=description
                )
            )


            saved_vulnerabilities.append(
                vulnerability
            )


        # ====================================================
        # REPORT
        # ====================================================

        report = Report.objects.create(
            scan=scan,
            report_file=""
        )


    # ========================================================
    # 6. TERMINAL OUTPUT
    # ========================================================

    print(
        f"[VULNEX] User PK: "
        f"{user.pk}"
    )


    print(
        f"[VULNEX] Scan Owner: "
        f"{user.full_name}"
    )


    print(
        f"[VULNEX] Website PK: "
        f"{website.pk}"
    )


    print(
        f"[VULNEX] Scan PK: "
        f"{scan.pk}"
    )


    print(
        f"[VULNEX] Findings Saved: "
        f"{len(saved_vulnerabilities)}"
    )


    print(
        "[VULNEX] Scan Complete!\n"
    )


    # ========================================================
    # 7. RETURN RESULT
    # ========================================================

    return {

        "url":
        normalized_url,

        "vector":
        binary_vector,

        "vulnerability_details":
        vulnerability_details,

        "issues":
        issues,

        "risk_category":
        risk_level,

        "security_score":
        db_security_score,

        "confidence":
        confidence,

        "user_id":
        user.pk,

        "user_name":
        user.full_name,

        "scan_id":
        scan.pk,

        "website_id":
        website.pk,

        "report_id":
        report.pk,

        "ai_prediction":
        ai_results,

        "source":
        source_engine
    }