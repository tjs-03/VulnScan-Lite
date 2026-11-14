let latestReport = null;

async function startScan() {
    const urlInput = document.getElementById("urlInput");
    const scanBtn = document.getElementById("scanBtn");
    const statusBox = document.getElementById("statusBox");
    const statusText = document.getElementById("statusText");
    const errorBox = document.getElementById("errorBox");
    const resultsSection = document.getElementById("resultsSection");

    const url = urlInput.value.trim();
    if (!url) {
        showError("Please enter a valid target URL.");
        return;
    }

    // Reset UI
    latestReport = null;
    errorBox.classList.add("hidden");
    resultsSection.classList.add("hidden");
    statusBox.classList.remove("hidden");
    statusText.textContent = "Queuing passive security scan...";
    scanBtn.disabled = true;

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Failed to start scan.");
        }

        pollScanStatus(data.job_id);
    } catch (err) {
        statusBox.classList.add("hidden");
        scanBtn.disabled = false;
        showError(err.message);
    }
}

function pollScanStatus(jobId) {
    const statusText = document.getElementById("statusText");
    const statusBox = document.getElementById("statusBox");
    const scanBtn = document.getElementById("scanBtn");

    const interval = setInterval(async () => {
        try {
            const res = await fetch(`/api/status/${jobId}`);
            const job = await res.json();

            if (!res.ok) {
                clearInterval(interval);
                statusBox.classList.add("hidden");
                scanBtn.disabled = false;
                showError(job.error || "Error fetching scan status.");
                return;
            }

            if (job.status === "running" || job.status === "queued") {
                statusText.textContent = `Scanning target (${job.status})...`;
            } else if (job.status === "completed") {
                clearInterval(interval);
                statusBox.classList.add("hidden");
                scanBtn.disabled = false;
                renderResults(job.result);
            } else if (job.status === "failed") {
                clearInterval(interval);
                statusBox.classList.add("hidden");
                scanBtn.disabled = false;
                showError(job.error || "Scan failed.");
            }
        } catch (err) {
            clearInterval(interval);
            statusBox.classList.add("hidden");
            scanBtn.disabled = false;
            showError("Network error while checking scan progress.");
        }
    }, 1500);
}

function renderResults(result) {
    latestReport = result;

    const resultsSection = document.getElementById("resultsSection");
    const gradeBadge = document.getElementById("gradeBadge");

    document.getElementById("targetTitle").textContent = result.target_url;
    document.getElementById("scoreValue").textContent = result.score;
    document.getElementById("cmsValue").textContent = result.detected_cms.join(", ");

    const ssl = result.ssl_details;
    document.getElementById("sslValue").textContent = ssl.valid
        ? `${ssl.tls_version} (${ssl.days_left} days left)`
        : "Invalid / No HTTPS";

    gradeBadge.textContent = result.grade;
    gradeBadge.className = "score-circle";
    if (result.score < 50) gradeBadge.classList.add("low");
    else if (result.score < 80) gradeBadge.classList.add("mid");

    // Failed checks
    const failedList = document.getElementById("failedList");
    failedList.innerHTML = "";
    document.getElementById("failCount").textContent = result.failed_checks.length;

    if (result.failed_checks.length === 0) {
        failedList.innerHTML = `<p class="check-desc">No vulnerabilities or missing headers detected!</p>`;
    } else {
        result.failed_checks.forEach(item => {
            failedList.innerHTML += `
                <div class="check-item fail">
                    <div class="check-title">${item.check}</div>
                    <div class="remediation-box">Fix: ${item.remediation}</div>
                </div>
            `;
        });
    }

    // Passed checks
    const passedList = document.getElementById("passedList");
    passedList.innerHTML = "";
    document.getElementById("passCount").textContent = result.passed_checks.length;

    result.passed_checks.forEach(item => {
        passedList.innerHTML += `
            <div class="check-item pass">
                <div class="check-title">${item.check}</div>
                <div class="check-desc">${item.details}</div>
            </div>
        `;
    });

    resultsSection.classList.remove("hidden");
}

function downloadReport() {
    if (!latestReport) return;
    const blob = new Blob([JSON.stringify(latestReport, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `vulnscan-report-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
}

function showError(msg) {
    const errorBox = document.getElementById("errorBox");
    errorBox.textContent = msg;
    errorBox.classList.remove("hidden");
}
