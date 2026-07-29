import requests
import socket
import ssl
from urllib.parse import urlparse
from bs4 import BeautifulSoup

class VulnexFeatureExtractor:
    def __init__(self, timeout=5):
        self.timeout = timeout
        
        # We are looking for these 8 specific security features.
        # This will result in a binary vector of length 8.
        self.feature_names = [
            "missing_strict_transport_security",
            "missing_x_frame_options",
            "missing_x_content_type_options",
            "missing_content_security_policy",
            "server_header_exposed",
            "x_powered_by_exposed",
            "weak_ssl_certificate",
            "directory_listing_exposed"
        ]

    def _check_ssl(self, hostname):
        """Attempts to verify the SSL certificate of the target."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # If we successfully connect and wrap the socket, SSL is valid
                    return 0 
        except Exception:
            # Any error (expired, mismatched hostname, no SSL) means it's weak/invalid
            return 1

    def _check_directory_listing(self, html_content):
        """Uses BeautifulSoup to look for default Apache/Nginx directory indexes."""
        if not html_content:
            return 0
        soup = BeautifulSoup(html_content, 'html.parser')
        title = soup.title.string if soup.title else ""
        
        # Common signatures of exposed directories
        if "Index of /" in title or "Directory Listing For" in title:
            return 1
        return 0

    def extract_features(self, target_url):
        """
        Probes the URL and returns a dictionary of vulnerabilities 
        and the final binary vector.
        """
        # Ensure the URL is properly formatted
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url

        parsed_url = urlparse(target_url)
        hostname = parsed_url.hostname

        # Initialize our result dictionary with everything marked as secure (0)
        vulnerabilities = {feature: 0 for feature in self.feature_names}

        try:
            # 1. Probe the target (using a standard User-Agent to avoid basic blocks)
            headers = {'User-Agent': 'VulnEx-Scanner/1.0 (MCA Project)'}
            response = requests.get(target_url, headers=headers, timeout=self.timeout, verify=False)
            
            # Extract headers for analysis
            resp_headers = {k.lower(): v.lower() for k, v in response.headers.items()}

            # 2. Check Security Headers (1 = Missing/Vulnerable, 0 = Present/Secure)
            if 'strict-transport-security' not in resp_headers:
                vulnerabilities['missing_strict_transport_security'] = 1
                
            if 'x-frame-options' not in resp_headers:
                vulnerabilities['missing_x_frame_options'] = 1
                
            if 'x-content-type-options' not in resp_headers:
                vulnerabilities['missing_x_content_type_options'] = 1
                
            if 'content-security-policy' not in resp_headers:
                vulnerabilities['missing_content_security_policy'] = 1

            # 3. Check Information Exposure (1 = Exposed/Vulnerable, 0 = Hidden/Secure)
            if 'server' in resp_headers:
                vulnerabilities['server_header_exposed'] = 1
                
            if 'x-powered-by' in resp_headers:
                vulnerabilities['x_powered_by_exposed'] = 1

            # 4. Content Inspection (Directory Listing)
            vulnerabilities['directory_listing_exposed'] = self._check_directory_listing(response.text)

        except requests.exceptions.RequestException as e:
            # If the request fails entirely, we flag headers as missing/vulnerable
            # to be safe, but log that it was unreachable.
            print(f"[VULNEX EXTRACTOR] Connection failed for {target_url}: {e}")
            for key in vulnerabilities:
                vulnerabilities[key] = 1 

        # 5. Check SSL independently of the HTTP request
        if hostname:
            vulnerabilities['weak_ssl_certificate'] = self._check_ssl(hostname)

        # 6. Generate the binary vector in the exact order of self.feature_names
        binary_vector = [vulnerabilities[feature] for feature in self.feature_names]

        return {
            "target": target_url,
            "vulnerability_dict": vulnerabilities,
            "feature_vector": binary_vector
        }

# ==========================================
# TEST BLOCK - Run this file directly to test
# ==========================================
if __name__ == "__main__":
    import urllib3
    # Suppress InsecureRequestWarning for testing
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    extractor = VulnexFeatureExtractor()
    
    # Test on a known site (you can change this to a vulnerable test site)
    test_url = "http://neverssl.com" 
    
    print(f"Starting extraction on: {test_url}")
    results = extractor.extract_features(test_url)
    
    print("\n--- EXTRACTION COMPLETE ---")
    print("\nHuman Readable Dictionary:")
    for key, value in results['vulnerability_dict'].items():
        print(f"  {key}: {value}")
        
    print(f"\nMachine Learning Vector:")
    print(f"  {results['feature_vector']}")


    