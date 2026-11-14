import time
import uuid
import socket
import ipaddress
import threading
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from scanner import run_full_scan

app = Flask(__name__)
CORS(app)

scan_jobs = {}
rate_limit_store = {}
MAX_REQUESTS_PER_MINUTE = 5

def is_safe_target(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
    except Exception:
        return False

def is_rate_limited(ip_address):
    now = time.time()
    window_start = now - 60
    timestamps = [t for t in rate_limit_store.get(ip_address, []) if t > window_start]
    if len(timestamps) >= MAX_REQUESTS_PER_MINUTE:
        rate_limit_store[ip_address] = timestamps
        return True
    timestamps.append(now)
    rate_limit_store[ip_address] = timestamps
    return False

def background_scan_worker(job_id, target_url):
    try:
        scan_jobs[job_id]["status"] = "running"
        result = run_full_scan(target_url)
        scan_jobs[job_id]["status"] = "completed"
        scan_jobs[job_id]["result"] = result
    except Exception as e:
        scan_jobs[job_id]["status"] = "failed"
        scan_jobs[job_id]["error"] = str(e)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def start_scan():
    client_ip = request.remote_addr or "127.0.0.1"
    if is_rate_limited(client_ip):
        return jsonify({"error": "Rate limit exceeded. Maximum 5 scans per minute allowed."}), 429

    data = request.get_json(silent=True) or {}
    target_url = data.get("url", "").strip()

    if not target_url:
        return jsonify({"error": "Please provide a valid URL."}), 400

    if not is_safe_target(target_url):
        return jsonify({"error": "Blocked: Localhost, private IPs, or unreachable domains are not allowed."}), 400

    job_id = str(uuid.uuid4())
    scan_jobs[job_id] = {
        "job_id": job_id,
        "target_url": target_url,
        "status": "queued",
        "result": None,
        "error": None
    }

    thread = threading.Thread(target=background_scan_worker, args=(job_id, target_url), daemon=True)
    thread.start()

    return jsonify({"job_id": job_id, "status": "queued", "message": "Scan started in background."}), 202

@app.route("/api/status/<job_id>", methods=["GET"])
def get_scan_status(job_id):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job ID not found."}), 404
    return jsonify(job), 200

if __name__ == "__main__":
    app.run(debug=True, port=5000)
