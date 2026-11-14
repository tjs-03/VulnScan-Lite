import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "fix": "Add 'add_header Content-Security-Policy \"default-src 'self';\";' to your Nginx/Apache config."
    },
    "X-Frame-Options": {
        "fix": "Add 'add_header X-Frame-Options \"SAMEORIGIN\";' to prevent Clickjacking attacks."
    },
    "Strict-Transport-Security": {
        "fix": "Add 'add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\";' to enforce HTTPS."
    },
    "X-Content-Type-Options": {
        "fix": "Add 'add_header X-Content-Type-Options \"nosniff\";' to prevent MIME-sniffing."
    },
    "Referrer-Policy": {
        "fix": "Add 'add_header Referrer-Policy \"no-referrer-when-downgrade\";' to control referrer info."
    }
}

def analyze_headers(url):
    passed = []
    failed = []
    score_change = 0

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in response.headers.items()}

        for header_name, info in SECURITY_HEADERS.items():
            if header_name.lower() in headers:
                passed.append({
                    "check": f"Security Header: {header_name}",
                    "status": "PASS",
                    "details": f"Present ({headers[header_name.lower()][:40]}...)"
                })
                score_change += 10
            else:
                failed.append({
                    "check": f"Missing Header: {header_name}",
                    "status": "FAIL",
                    "remediation": info["fix"]
                })
                score_change -= 10

        return {
            "passed": passed,
            "failed": failed,
            "score_delta": score_change,
            "raw_headers": dict(response.headers),
            "html": response.text
        }
    except Exception as e:
        return {
            "error": str(e),
            "passed": [],
            "failed": [{
                "check": "HTTP Connection",
                "status": "FAIL",
                "remediation": "Ensure the target URL is reachable and online."
            }],
            "score_delta": -20,
            "raw_headers": {},
            "html": ""
        }
