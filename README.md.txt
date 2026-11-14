# 🛡️ VulnScan-Lite

A passive web vulnerability and security posture scanner built with Python and Flask. VulnScan-Lite analyzes target websites non-intrusively for missing HTTP security headers, SSLTLS certificate health, cipher strength, and exposed CMSserver technologies, generating an actionable security grade (A+ to F) with remediation snippets.

## ✨ Features
- HTTP Security Headers Audit Checks for `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`, and `Referrer-Policy`.
- SSLTLS Inspection Validates certificate expiration days, TLS protocol version (TLSv1.21.3), and cipher suite bit strength.
- Tech & CMS Fingerprinting Detects exposed `X-Powered-By` headers and `meta name=generator` tags.
- Asynchronous Background Scanning Non-blocking scan queue with live status polling.
- Built-in Abuse Protection IP-based rate limiting (5 scansmin) and SSRF prevention against privatelocalhost targets.
- Exportable Reports One-click JSON security report download.

## 🚀 Quick Start

1. Clone the repository
   ```bash
   git clone httpsgithub.com
   cd VulnScan-Lite
   ```

2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application
   ```bash
   python app.py
   ```

4. Open in browser
   Navigate to `http127.0.0.15000`

## ⚠️ Disclaimer
This tool performs passive reconnaissance only and is intended for educational and authorized security auditing purposes.
