import requests
import ssl
import socket
import urllib.parse
import urllib3
import re


# Suppress warnings because the HTTP inspection
# intentionally continues even for invalid certificates.
urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


class VulnexFeatureExtractor:

    def __init__(self, timeout=5):

        self.timeout = timeout

        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }


    def extract_features(self, target_url):
        """
        Returns:
        - URL
        - 12-bit feature vector
        - vulnerability flags
        - site-specific Issue evidence
        """

        # ============================================================
        # NORMALIZE URL
        # ============================================================

        if not target_url.startswith(
            ("http://", "https://")
        ):
            target_url = (
                "https://" + target_url
            )

        parsed_url = urllib.parse.urlparse(
            target_url
        )

        domain = parsed_url.hostname


        # ============================================================
        # FEATURE FLAGS
        # ============================================================

        missing_hsts = 0
        missing_x_frame = 0
        missing_x_content_type = 0
        missing_csp = 0

        exposed_server = 0
        exposed_x_powered_by = 0

        weak_ssl = 0
        exposed_dir_listing = 0

        missing_httponly = 0
        missing_secure = 0

        cors_wildcard = 0
        outdated_cms = 0


        # ============================================================
        # ACTUAL ISSUE EVIDENCE
        # ============================================================

        issues = {}


        # ============================================================
        # 1. SSL / TLS
        # ============================================================

        if parsed_url.scheme == "http":

            weak_ssl = 1

            issues[
                "weak_ssl_certificate"
            ] = (
                "Target uses HTTP instead of HTTPS"
            )

        else:

            try:

                ssl_context = (
                    ssl.create_default_context()
                )

                with socket.create_connection(
                    (domain, 443),
                    timeout=self.timeout
                ) as sock:

                    with ssl_context.wrap_socket(
                        sock,
                        server_hostname=domain
                    ) as ssl_socket:

                        ssl_socket.getpeercert()

            except Exception as exc:

                weak_ssl = 1

                issues[
                    "weak_ssl_certificate"
                ] = (
                    "SSL/TLS validation failed: "
                    f"{exc}"
                )


        # ============================================================
        # 2. HTTP RESPONSE
        # ============================================================

        try:

            response = requests.get(
                target_url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )

            final_url = response.url

            headers = {
                key.lower(): value
                for key, value
                in response.headers.items()
            }

            body_text = (
                response.text.lower()
            )


            # ========================================================
            # 1 — MISSING HSTS
            # ========================================================

            if (
                "strict-transport-security"
                not in headers
            ):

                missing_hsts = 1

                issues[
                    "missing_hsts"
                ] = (
                    "Strict-Transport-Security "
                    "header not found in HTTP "
                    f"response from {final_url}"
                )


            # ========================================================
            # 2 — MISSING X-FRAME-OPTIONS
            # ========================================================

            if (
                "x-frame-options"
                not in headers
            ):

                missing_x_frame = 1

                issues[
                    "missing_x_frame_options"
                ] = (
                    "X-Frame-Options header "
                    "not found in HTTP response "
                    f"from {final_url}"
                )


            # ========================================================
            # 3 — MISSING X-CONTENT-TYPE-OPTIONS
            # ========================================================

            if (
                "x-content-type-options"
                not in headers
            ):

                missing_x_content_type = 1

                issues[
                    "missing_x_content_type_options"
                ] = (
                    "X-Content-Type-Options "
                    "header not found in HTTP "
                    f"response from {final_url}"
                )


            # ========================================================
            # 4 — MISSING CSP
            # ========================================================

            if (
                "content-security-policy"
                not in headers
            ):

                missing_csp = 1

                issues[
                    "missing_csp"
                ] = (
                    "Content-Security-Policy "
                    "header not found in HTTP "
                    f"response from {final_url}"
                )


            # ========================================================
            # 5 — EXPOSED SERVER HEADER
            # ========================================================

            server_header = headers.get(
                "server",
                ""
            ).strip()

            if server_header:

                version_match = re.search(
                    r"\b\d+(?:\.\d+){1,4}\b",
                    server_header
                )

                if version_match:

                    exposed_server = 1

                    issues[
                        "exposed_server_header"
                    ] = (
                        "Server software/version exposed "
                        "in Server header: "
                        f"{server_header} "
                        f"on {final_url}"
                    )


            # ========================================================
            # 6 — EXPOSED X-POWERED-BY
            # ========================================================

            powered_by = headers.get(
                "x-powered-by",
                ""
            ).strip()

            if powered_by:

                exposed_x_powered_by = 1

                issues[
                    "exposed_x_powered_by"
                ] = (
                    "X-Powered-By header "
                    f"exposed: {powered_by}"
                )


            # ========================================================
            # 7 — DIRECTORY LISTING
            # ========================================================

            directory_indicators = [
                "index of /",
                "directory listing for",
                "parent directory",
            ]

            for indicator in (
                directory_indicators
            ):

                if indicator in body_text:

                    exposed_dir_listing = 1

                    issues[
                        "exposed_dir_listing"
                    ] = (
                        "Directory listing "
                        f'indicator "{indicator}" '
                        f"found at {final_url}"
                    )

                    break


            # ========================================================
            # 8 / 9 — COOKIE FLAGS
            # ========================================================

            set_cookie_header = (
                headers.get(
                    "set-cookie",
                    ""
                )
            )

            if (
                response.cookies
                or set_cookie_header
            ):

                cookie_names = [
                    cookie.name
                    for cookie
                    in response.cookies
                ]

                cookie_display = (
                    ", ".join(cookie_names)
                    if cookie_names
                    else "Response cookie"
                )


                # Missing HttpOnly

                if (
                    "httponly"
                    not in
                    set_cookie_header.lower()
                ):

                    missing_httponly = 1

                    issues[
                        "missing_httponly_cookie"
                    ] = (
                        f'Cookie "{cookie_display}" '
                        "is missing HttpOnly flag"
                    )


                # Missing Secure

                if (
                    "secure"
                    not in
                    set_cookie_header.lower()
                ):

                    missing_secure = 1

                    issues[
                        "missing_secure_cookie"
                    ] = (
                        f'Cookie "{cookie_display}" '
                        "is missing Secure flag"
                    )


            # ========================================================
            # 10 — CORS WILDCARD
            # ========================================================

            cors_header = headers.get(
                "access-control-allow-origin",
                ""
            ).strip()

            if cors_header == "*":

                cors_wildcard = 1

                issues[
                    "cors_wildcard"
                ] = (
                    "Access-Control-Allow-Origin: * "
                    f"returned by {final_url}"
                )


            # ========================================================
            # 11 — CMS / TECHNOLOGY SIGNATURE
            # ========================================================

            cms_header_values = []

            cms_headers = [
                "x-generator",
                "x-drupal-cache",
                "x-redirect-by",
            ]

            for header in cms_headers:

                if header in headers:

                    cms_header_values.append(
                        f"{header}: "
                        f"{headers[header]}"
                    )


            cms_keywords = {

                "wordpress": [
                    "wp-content",
                    "wordpress",
                    'generator="wordpress',
                ],

                "drupal": [
                    "drupal",
                ],

                "joomla": [
                    "joomla",
                ],
            }


            detected_cms = None

            for (
                cms_name,
                keywords
            ) in cms_keywords.items():

                if any(
                    keyword in body_text
                    for keyword in keywords
                ):

                    detected_cms = (
                        cms_name
                    )

                    break


            if (
                cms_header_values
                or detected_cms
            ):

                outdated_cms = 1

                if cms_header_values:

                    issues[
                        "outdated_cms_header"
                    ] = (
                        "CMS/technology "
                        "signature detected: "
                        + " | ".join(
                            cms_header_values
                        )
                    )

                elif detected_cms:

                    issues[
                        "outdated_cms_header"
                    ] = (
                        "CMS signature detected "
                        "in page: "
                        f"{detected_cms}"
                    )


        # ============================================================
        # HTTP REQUEST FAILED
        # ============================================================

        except Exception as exc:

            issues[
                "connection_error"
            ] = str(exc)


        # ============================================================
        # 12-BIT FEATURE VECTOR
        #
        # DO NOT CHANGE THIS ORDER WITHOUT RETRAINING THE MODEL
        # ============================================================

        feature_vector = [

            int(
                missing_hsts
            ),

            int(
                missing_x_frame
            ),

            int(
                missing_x_content_type
            ),

            int(
                missing_csp
            ),

            int(
                exposed_server
            ),

            int(
                exposed_x_powered_by
            ),

            int(
                weak_ssl
            ),

            int(
                exposed_dir_listing
            ),

            int(
                missing_httponly
            ),

            int(
                missing_secure
            ),

            int(
                cors_wildcard
            ),

            int(
                outdated_cms
            ),
        ]


        # ============================================================
        # RETURN RESULT
        # ============================================================

        return {

            "url":
                target_url,

            "feature_vector":
                feature_vector,

            "details": {

                "missing_hsts":
                    bool(
                        missing_hsts
                    ),

                "missing_x_frame_options":
                    bool(
                        missing_x_frame
                    ),

                "missing_x_content_type_options":
                    bool(
                        missing_x_content_type
                    ),

                "missing_csp":
                    bool(
                        missing_csp
                    ),

                "exposed_server_header":
                    bool(
                        exposed_server
                    ),

                "exposed_x_powered_by":
                    bool(
                        exposed_x_powered_by
                    ),

                "weak_ssl_certificate":
                    bool(
                        weak_ssl
                    ),

                "exposed_dir_listing":
                    bool(
                        exposed_dir_listing
                    ),

                "missing_httponly_cookie":
                    bool(
                        missing_httponly
                    ),

                "missing_secure_cookie":
                    bool(
                        missing_secure
                    ),

                "cors_wildcard":
                    bool(
                        cors_wildcard
                    ),

                "outdated_cms_header":
                    bool(
                        outdated_cms
                    ),
            },

            # IMPORTANT:
            # This feeds the Issue column
            # in your report.
            "issues":
                issues,
        }