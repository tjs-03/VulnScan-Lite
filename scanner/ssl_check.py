import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

def inspect_ssl(url):
    passed = []
    failed = []
    parsed = urlparse(url)
    hostname = parsed.hostname

    if parsed.scheme != "https":
        failed.append({
            "check": "HTTPS / SSL Encryption",
            "status": "FAIL",
            "remediation": "Install an SSL/TLS certificate (e.g., via Let's Encrypt) and redirect HTTP to HTTPS."
        })
        return {"passed": passed, "failed": failed, "ssl_details": {"valid": False}}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

                # Expiry Date Check
                not_after_str = cert['notAfter']
                expiry_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry_date - datetime.utcnow()).days

                if days_left > 0:
                    passed.append({
                        "check": "SSL Certificate Validity",
                        "status": "PASS",
                        "details": f"Valid (Expires in {days_left} days on {expiry_date.strftime('%Y-%m-%d')})"
                    })
                else:
                    failed.append({
                        "check": "SSL Certificate Expired",
                        "status": "FAIL",
                        "remediation": "Renew your SSL/TLS certificate immediately."
                    })

                # Cipher Strength Check
                cipher_name, tls_version, key_bits = cipher
                if key_bits >= 128 and tls_version in ["TLSv1.2", "TLSv1.3"]:
                    passed.append({
                        "check": "TLS Protocol & Cipher Strength",
                        "status": "PASS",
                        "details": f"{tls_version} using {cipher_name} ({key_bits}-bit)"
                    })
                else:
                    failed.append({
                        "check": "Weak TLS / Cipher Configuration",
                        "status": "FAIL",
                        "remediation": "Disable TLS 1.0/1.1 and weak ciphers; enforce TLS 1.2 or TLS 1.3."
                    })

                return {
                    "passed": passed,
                    "failed": failed,
                    "ssl_details": {
                        "valid": days_left > 0,
                        "days_left": days_left,
                        "tls_version": tls_version,
                        "cipher": cipher_name
                    }
                }
    except Exception as e:
        failed.append({
            "check": "SSL/TLS Handshake",
            "status": "FAIL",
            "remediation": f"Fix SSL configuration error: {str(e)}"
        })
        return {"passed": passed, "failed": failed, "ssl_details": {"valid": False}}
