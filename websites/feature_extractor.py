import requests
import ssl
import socket
import urllib.parse
import urllib3

# Suppress SSL warnings when inspecting unverified target certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VulnexFeatureExtractor:

    def __init__(self, timeout=5):
        self.timeout = timeout
        self.headers = {
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/120.0.0.0 Safari/537.36'
            )
        }

    def extract_features(self, target_url):
        """
        Scans a target URL and returns a 12-bit binary feature vector 
        matching the exact structure of vulnex_dataset.csv.
        """
        # Ensure scheme is prepended
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        parsed_url = urllib.parse.urlparse(target_url)
        domain = parsed_url.netloc or parsed_url.path

        # Feature flags initialization (0 = Safe / False, 1 = Vulnerable / True)
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

        # -------------------------------------------------------------
        # 1. SSL/TLS Certificate Validation Check
        # -------------------------------------------------------------
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssock.getpeercert()
        except Exception:
            # Self-signed, expired, weak cipher, or HTTP-only site
            weak_ssl = 1

        # -------------------------------------------------------------
        # 2. Web Response & Header Analysis
        # -------------------------------------------------------------
        try:
            response = requests.get(
                target_url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False,  # Proceed with HTTP inspection even if SSL is invalid
                allow_redirects=True
            )

            # Normalize headers to lowercase for easy lookup
            headers = {k.lower(): v for k, v in response.headers.items()}
            body_text = response.text.lower()

            # Feature 1: Missing HSTS
            if 'strict-transport-security' not in headers:
                missing_hsts = 1

            # Feature 2: Missing X-Frame-Options (Clickjacking)
            if 'x-frame-options' not in headers:
                missing_x_frame = 1

            # Feature 3: Missing X-Content-Type-Options (MIME Sniffing)
            if 'x-content-type-options' not in headers:
                missing_x_content_type = 1

            # Feature 4: Missing Content-Security-Policy (CSP)
            if 'content-security-policy' not in headers:
                missing_csp = 1

            # Feature 5: Exposed Server Banner
            if 'server' in headers and headers['server'].strip():
                exposed_server = 1

            # Feature 6: Exposed X-Powered-By Header
            if 'x-powered-by' in headers:
                exposed_x_powered_by = 1

            # Feature 7: Exposed Directory Listing
            dir_indicators = ['index of /', 'directory listing for', 'parent directory']
            if any(indicator in body_text for indicator in dir_indicators):
                exposed_dir_listing = 1

            # Features 8 & 9: Cookie Flag Inspections
            set_cookie_header = headers.get('set-cookie', '')
            if response.cookies or set_cookie_header:
                if 'httponly' not in set_cookie_header.lower():
                    missing_httponly = 1
                if 'secure' not in set_cookie_header.lower():
                    missing_secure = 1

            # Feature 10: CORS Wildcard Configuration
            cors_header = headers.get('access-control-allow-origin', '')
            if cors_header == '*':
                cors_wildcard = 1

            # Feature 11: Outdated CMS / Technology Signatures
            cms_headers = ['x-generator', 'x-drupal-cache', 'x-redirect-by']
            has_cms_header = any(h in headers for h in cms_headers)
            cms_keywords = ['wp-content', 'wordpress', 'drupal', 'joomla', 'generator="wordpress']
            has_cms_body = any(k in body_text for k in cms_keywords)

            if has_cms_header or has_cms_body:
                outdated_cms = 1

        except Exception:
            # Fallback if connection times out or fails completely
            missing_hsts = 1
            missing_csp = 1

        # -------------------------------------------------------------
        # 3. Assemble 12-Bit Feature Vector
        # -------------------------------------------------------------
        feature_vector = [
            int(missing_hsts),
            int(missing_x_frame),
            int(missing_x_content_type),
            int(missing_csp),
            int(exposed_server),
            int(exposed_x_powered_by),
            int(weak_ssl),
            int(exposed_dir_listing),
            int(missing_httponly),
            int(missing_secure),
            int(cors_wildcard),
            int(outdated_cms)
        ]

        return {
            'url': target_url,
            'feature_vector': feature_vector,
            'details': {
                'missing_hsts': bool(missing_hsts),
                'missing_x_frame_options': bool(missing_x_frame),
                'missing_x_content_type_options': bool(missing_x_content_type),
                'missing_csp': bool(missing_csp),
                'exposed_server_header': bool(exposed_server),
                'exposed_x_powered_by': bool(exposed_x_powered_by),
                'weak_ssl_certificate': bool(weak_ssl),
                'exposed_dir_listing': bool(exposed_dir_listing),
                'missing_httponly_cookie': bool(missing_httponly),
                'missing_secure_cookie': bool(missing_secure),
                'cors_wildcard': bool(cors_wildcard),
                'outdated_cms_header': bool(outdated_cms)
            }
        }