from bs4 import BeautifulSoup

def detect_cms(html_content, raw_headers):
    passed = []
    failed = []
    detected_tech = []

    # 1. Check X-Powered-By Header
    headers_lower = {k.lower(): v for k, v in raw_headers.items()}
    if "x-powered-by" in headers_lower:
        val = headers_lower["x-powered-by"]
        detected_tech.append(f"Header X-Powered-By: {val}")
        failed.append({
            "check": f"Exposed Server Technology ({val})",
            "status": "FAIL",
            "remediation": "Hide the 'X-Powered-By' header in your server/PHP config to prevent version fingerprinting."
        })
    else:
        passed.append({
            "check": "Server Technology Header Hidden",
            "status": "PASS",
            "details": "X-Powered-By header is not exposed."
        })

    # 2. Check HTML <meta name="generator"> tag
    if html_content:
        soup = BeautifulSoup(html_content, "html.parser")
        generator_meta = soup.find("meta", attrs={"name": "generator"})
        if generator_meta and generator_meta.get("content"):
            cms_name = generator_meta.get("content")
            detected_tech.append(f"CMS Meta Generator: {cms_name}")
            failed.append({
                "check": f"Exposed CMS Version ({cms_name})",
                "status": "FAIL",
                "remediation": f"Remove the <meta name='generator'> tag and ensure {cms_name} is updated to the latest patch."
            })
        else:
            passed.append({
                "check": "CMS Generator Meta Tag Hidden",
                "status": "PASS",
                "details": "No exposed CMS generator meta tags found."
            })

    return {
        "passed": passed,
        "failed": failed,
        "detected_tech": detected_tech if detected_tech else ["None Detected"]
    }
