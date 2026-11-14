# 🛡️ VulnScan-Lite

**VulnScan-Lite** is a lightweight, passive web vulnerability and security posture scanner built with **Python** and **Flask**. It performs non-intrusive reconnaissance on target web applications to audit HTTP security headers, SSL/TLS certificate health, cipher strength, and exposed CMS/server technologies—generating an actionable security score (0–100), letter grade (`A+` to `F`), and server-specific remediation snippets.

---

## ✨ Key Features

- **🔒 HTTP Security Headers Audit:** Inspects responses for critical defense-in-depth headers (`Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`, and `Referrer-Policy`) and provides exact Nginx/Apache configuration fixes for missing headers.
- **📜 SSL/TLS Certificate & Cipher Inspection:** Connects over TLS to verify certificate validity, remaining days until expiration, TLS protocol version (`TLSv1.2` / `TLSv1.3`), and encryption key bit strength.
- **🔍 Tech & CMS Fingerprinting:** Detects information leakage via `X-Powered-By` response headers and HTML `<meta name="generator">` tags.
- **⚡ Asynchronous Background Scanning:** Uses a threaded job queue (`/api/scan` & `/api/status/<job_id>`) so the web dashboard remains responsive while scans run in the background.
- **🛡️ Built-in Abuse & SSRF Protection:**
  - **SSRF Prevention:** Blocks scanning of `localhost`, loopback, reserved, and private RFC1918 IP ranges (`127.0.0.1`, `192.168.x.x`, `10.x.x.x`).
  - **Rate Limiting:** Enforces an IP-based limit of 5 scans per minute to prevent abuse.
- **📥 Exportable JSON Reports:** One-click download of full scan results in structured `.json` format for documentation or further analysis.

---

## 📂 Project Structure

```text
VulnScan-Lite/
├── app.py                  # Flask backend API, async job queue, SSRF & rate limiter
├── requirements.txt        # Python dependencies
├── README.md               # Project documentation
├── scanner/                # Core passive scanning package
│   ├── __init__.py         # Orchestrates scans & calculates 0-100 score / grade
│   ├── headers.py          # HTTP security headers analyzer
│   ├── ssl_check.py        # SSL/TLS certificate & cipher suite inspector
│   └── cms_detect.py       # Server & CMS fingerprinting module
├── templates/
│   └── index.html          # Web dashboard UI
└── static/
    ├── style.css           # Dark-mode cybersecurity dashboard styling
    └── script.js           # Frontend polling, rendering & JSON export logic
```

---

## 🚀 Installation & Local Setup

### Prerequisites
- Python **3.9+** installed on your system
- `pip` (Python package manager)

### Step-by-Step Guide

1. **Clone the repository:**
   ```bash
   git clone https://github.com
   cd VulnScan-Lite
   ```

2. **Install the required Python libraries:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the Flask server:**
   ```bash
   python app.py
   ```

4. **Access the Web Dashboard:**
   Open your browser and go to:
   ```text
   http://127.0.0.1:5000
   ```

---

## 🖥️ How to Use

1. Enter any public target URL (e.g., `https://example.com`) into the input bar on the dashboard.
2. Click **Scan Target**.
3. Wait a few seconds while the background worker audits headers, TLS configuration, and technology signatures.
4. Review your **Security Grade**, **Passed Checks**, and **Failed Checks with Remediation Fixes**.
5. Click **⬇️ Download JSON Report** to save a local copy of the scan results.

---

## 🔌 REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Serves the VulnScan-Lite web dashboard |
| `POST` | `/api/scan` | Queues a new passive scan (`{"url": "https://example.com"}`) |
| `GET` | `/api/status/<job_id>` | Polls the current status (`queued`, `running`, `completed`) and results of a scan |

---

## ⚠️ Legal & Ethical Disclaimer

**VulnScan-Lite** performs **passive reconnaissance only** (standard HTTP GET requests and TLS handshakes) and does not execute intrusive payloads or exploitation attempts. This tool is built strictly for educational purposes, defensive security auditing, and authorized testing. Always ensure you have permission before scanning target infrastructure.
