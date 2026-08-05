VULNERABILITY_DICT = {
    'missing_hsts': {
        'name': 'Missing HSTS Header',
        'description': 'HTTP Strict Transport Security is not enforced, leaving the site vulnerable to downgrade attacks.',
        'fix': 'Add the "Strict-Transport-Security" header to your web server configuration.'
    },
    'missing_x_frame_options': {
        'name': 'Missing X-Frame-Options',
        'description': 'The site can be embedded in iframes, exposing users to Clickjacking attacks.',
        'fix': 'Set the "X-Frame-Options" header to "DENY" or "SAMEORIGIN".'
    },
    'missing_x_content_type_options': {
        'name': 'Missing X-Content-Type-Options',
        'description': 'Browsers may sniff the MIME type, potentially executing malicious scripts.',
        'fix': 'Set the "X-Content-Type-Options" header to "nosniff".'
    },
    'missing_csp': {
        'name': 'Missing Content Security Policy (CSP)',
        'description': 'No CSP is defined, greatly increasing the risk of Cross-Site Scripting (XSS).',
        'fix': 'Implement a strict Content-Security-Policy header restricting script sources.'
    },
    'exposed_server_header': {
        'name': 'Exposed Server Version',
        'description': 'The server broadcasts its exact software version, aiding attackers in finding specific exploits.',
        'fix': 'Configure the web server to hide or spoof the "Server" header.'
    },
    'exposed_x_powered_by': {
        'name': 'Exposed X-Powered-By Header',
        'description': 'The backend technology stack is exposed.',
        'fix': 'Disable the "X-Powered-By" header in your application framework settings.'
    },
    'weak_ssl_certificate': {
        'name': 'Weak or Invalid SSL/TLS',
        'description': 'The SSL certificate is missing, expired, self-signed, or using weak ciphers.',
        'fix': 'Install a valid TLS certificate from a trusted CA and disable older TLS 1.0/1.1 protocols.'
    },
    'exposed_dir_listing': {
        'name': 'Directory Listing Enabled',
        'description': 'The web server allows users to browse internal folder structures.',
        'fix': 'Disable directory browsing/indexing in your web server configuration.'
    },
    'missing_httponly_cookie': {
        'name': 'Missing HttpOnly Cookie Flag',
        'description': 'Session cookies can be accessed via JavaScript, increasing XSS impact.',
        'fix': 'Set the "HttpOnly" flag on all session cookies.'
    },
    'missing_secure_cookie': {
        'name': 'Missing Secure Cookie Flag',
        'description': 'Cookies can be transmitted over unencrypted HTTP connections.',
        'fix': 'Set the "Secure" flag on all session cookies so they only transmit over HTTPS.'
    },
    'cors_wildcard': {
        'name': 'Insecure CORS Policy',
        'description': 'The Access-Control-Allow-Origin header is set to "*", allowing any domain to read data.',
        'fix': 'Restrict CORS headers to specific, trusted domains.'
    },
    'outdated_cms_header': {
        'name': 'Exposed/Outdated CMS Signatures',
        'description': 'Signatures indicate a CMS (like WordPress or Drupal) is exposed and potentially outdated.',
        'fix': 'Keep CMS software updated and use security plugins to strip generator meta tags.'
    }
}