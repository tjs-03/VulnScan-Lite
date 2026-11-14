from .headers import analyze_headers
from .ssl_check import inspect_ssl
from .cms_detect import detect_cms

def calculate_grade(score):
    if score >= 90:
        return "A+"
    elif score >= 80:
        return "A"
    elif score >= 70:
        return "B+"
    elif score >= 60:
        return "B"
    elif score >= 50:
        return "C"
    elif score >= 40:
        return "D"
    else:
        return "F"

def run_full_scan(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    header_res = analyze_headers(url)
    ssl_res = inspect_ssl(url)
    cms_res = detect_cms(header_res.get("html", ""), header_res.get("raw_headers", {}))

    all_passed = header_res["passed"] + ssl_res["passed"] + cms_res["passed"]
    all_failed = header_res["failed"] + ssl_res["failed"] + cms_res["failed"]

    # Base score 50 + header delta (+10/-10) + SSL/CMS adjustments
    raw_score = 50 + header_res["score_delta"]
    raw_score += (len(ssl_res["passed"]) * 10) - (len(ssl_res["failed"]) * 15)
    raw_score += (len(cms_res["passed"]) * 5) - (len(cms_res["failed"]) * 10)

    # Clamp score between 0 and 100
    final_score = max(0, min(100, raw_score))
    grade = calculate_grade(final_score)

    return {
        "target_url": url,
        "score": final_score,
        "grade": grade,
        "passed_checks": all_passed,
        "failed_checks": all_failed,
        "ssl_details": ssl_res["ssl_details"],
        "detected_cms": cms_res["detected_tech"]
    }
