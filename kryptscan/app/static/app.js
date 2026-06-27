const state = {
  email: "",
  dashboard: null,
  activeReport: null,
  activeScanId: null,
  assessmentMode: "vulnerability_assessment",
  scanTier: "free_preview",
  selectedService: "free_preview",
  refreshTimer: null,
};

const API_BASE = window.location.pathname.startsWith("/kryptscan") ? "/kryptscan-app" : "";

function apiPath(path) {
  return `${API_BASE}${path}`;
}

document.addEventListener("DOMContentLoaded", () => {
  bindEvent("registration-form", "submit", handleCompleteRegistration);
  bindEvent("scan-form", "submit", handleCreateScan);
  bindEvent("manual-finding-form", "submit", handleAddManualFinding);
  document.querySelectorAll("[data-plan]").forEach((button) => {
    button.addEventListener("click", () => handleCheckoutPlan(button.dataset.plan));
  });
  bindEvent("logout-button", "click", handleLogout);
  bindEvent("choice-logout-button", "click", handleLogout);
  bindEvent("report-download-button", "click", () => {
    if (state.activeScanId) downloadReport(state.activeScanId);
  });
  document.querySelectorAll("[data-assessment-mode]").forEach((button) => {
    button.addEventListener("click", () => selectAssessmentMode(button.dataset.assessmentMode));
  });
  document.querySelectorAll("[data-scan-tier]").forEach((button) => {
    button.addEventListener("click", () => selectScanTier(button.dataset.scanTier));
  });
  document.querySelectorAll("[data-choice-mode]").forEach((button) => {
    button.addEventListener("click", () => openSelectedTool(button.dataset.choiceMode, button.dataset.choiceTier));
  });
  handleVerificationRedirect();
  loadDashboard(false, { showChoiceWhenAuthenticated: true });
});

function routeParam(name) {
  return new URLSearchParams(window.location.search).get(name);
}

function bindEvent(id, eventName, handler) {
  const element = document.getElementById(id);
  if (element) element.addEventListener(eventName, handler);
}

function getCookie(name) {
  return document.cookie
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith(`${name}=`))
    ?.split("=")
    .slice(1)
    .join("=") || "";
}

function csrfHeaders() {
  const token = decodeURIComponent(getCookie("kryptnet_csrf"));
  return token ? { "X-CSRF-Token": token } : {};
}

function jsonHeaders() {
  return { "Content-Type": "application/json", ...csrfHeaders() };
}

function showOnly(sectionId) {
  ["landing-page", "verification-page", "registration-page", "tool-choice-page", "dashboard"].forEach((id) => {
    const element = document.getElementById(id);
    if (element) element.classList.toggle("hidden", id !== sectionId);
  });
}

function showVerificationPage() {
  showOnly("verification-page");
  window.location.hash = "verify-code";
}

function handleVerificationRedirect() {
  const params = new URLSearchParams(window.location.search);
  const sent = params.get("verification_sent");
  const verified = params.get("verified");
  const next = params.get("next");
  const delivery = params.get("delivery");
  const error = params.get("verification_error");
  const email = params.get("email");
  if (email) {
    const input = document.getElementById("email-input");
    if (input) input.value = email;
    state.email = email;
  }
  if (sent) {
    const message =
      delivery === "console"
        ? `Verification code was generated for ${email || "your email"}, but email delivery is in console mode. Check Render logs or set EMAIL_DELIVERY=smtp.`
        : `Verification code sent to ${email || "your email"}. Check your inbox and spam folder.`;
    setStatus("verify-status", message, delivery === "console" ? "error" : "success");
    showVerificationPage();
  }
  if (verified) {
    if (next === "choose-tool") {
      setStatus("dashboard-status", "Email verified. Choose a service to continue.", "success");
      showToolChoicePage();
    } else {
      setStatus("registration-status", "Email verified. Complete registration to continue.", "success");
      showRegistrationPage();
    }
  }
  if (error) {
    setStatus("auth-status", error, "error");
    if (window.location.hash === "#verify-code") {
      setStatus("verify-status", error, "error");
      showVerificationPage();
    } else {
      showOnly("landing-page");
    }
  }
}

function showToolChoicePage() {
  showOnly("tool-choice-page");
  window.location.hash = "choose-tool";
}

function showRegistrationPage() {
  showOnly("registration-page");
  window.location.hash = "register";
}

function showDashboardPage() {
  showOnly("dashboard");
  window.location.hash = "dashboard";
}

function openSelectedTool(mode, tier = null) {
  state.selectedService = tier === "free_preview" ? "free_preview" : mode;
  selectAssessmentMode(mode);
  if (tier) {
    selectScanTier(tier);
  }
  showDashboardPage();
  updateServiceWorkspace();
}

function selectAssessmentMode(mode) {
  state.assessmentMode = mode;
  const clientOnly = state.dashboard?.user?.role === "client_viewer";
  document.getElementById("assessment-mode-input").value = mode;
  document.querySelectorAll("[data-assessment-mode]").forEach((button) => {
    button.classList.toggle("active", button.dataset.assessmentMode === mode);
  });
  const submit = document.getElementById("scan-submit-button");
  const ethicalFields = document.getElementById("ethical-pentest-fields");
  if (ethicalFields) {
    ethicalFields.classList.toggle("hidden", clientOnly || mode !== "ethical_pentesting");
  }
  const tierSelector = document.getElementById("scan-tier-selector");
  if (mode === "ethical_pentesting") {
    selectScanTier("full_scan", { silent: true });
  } else if (!state.scanTier) {
    selectScanTier("free_preview", { silent: true });
  }
  if (tierSelector) {
    tierSelector.classList.toggle("hidden", clientOnly || mode !== "vulnerability_assessment");
  }
  updateScanSubmitText();
  const subtitle = document.getElementById("dashboard-subtitle");
  if (subtitle && state.dashboard) {
    subtitle.textContent =
      mode === "ethical_pentesting"
        ? `${state.dashboard.user.email} verified for ${state.dashboard.organization.domain}. Ethical Pen-Testing is paid-only and uses the approved target and full-stack testing tools.`
        : `${state.dashboard.user.email} verified for ${state.dashboard.organization.domain}. Choose a free preview or paid full vulnerability scan for an authorized asset.`;
  }
  if (state.dashboard) {
    renderCommercialReadiness(state.dashboard);
  }
  updateServiceWorkspace();
}

function selectScanTier(tier, options = {}) {
  state.scanTier = tier;
  if (tier === "free_preview") {
    state.selectedService = "free_preview";
  }
  document.getElementById("scan-tier-input").value = tier;
  document.querySelectorAll("[data-scan-tier]").forEach((button) => {
    button.classList.toggle("active", button.dataset.scanTier === tier);
  });
  updateScanSubmitText();
  if (!options.silent && state.dashboard) {
    renderCommercialReadiness(state.dashboard);
  }
  updateServiceWorkspace();
}

function updateScanSubmitText() {
  const submit = document.getElementById("scan-submit-button");
  if (!submit) return;
  if (state.assessmentMode === "ethical_pentesting") {
    submit.textContent = "Run Paid Ethical Pen-Testing";
  } else if (state.scanTier === "full_scan") {
    submit.textContent = "Run Full Vulnerability Scan";
  } else {
    submit.textContent = "Run Free Vulnerability Scan";
  }
}

function selectedServiceRequiresPayment() {
  return (
    state.assessmentMode === "ethical_pentesting" ||
    (state.assessmentMode === "vulnerability_assessment" && state.scanTier === "full_scan")
  );
}

function updateServiceWorkspace() {
  const paymentPanel = document.getElementById("payment-panel");
  const scanForm = document.getElementById("scan-form");
  const requiresPayment = selectedServiceRequiresPayment();

  if (paymentPanel) {
    paymentPanel.classList.toggle("hidden", !requiresPayment);
  }
  if (scanForm) {
    scanForm.classList.toggle("hidden", requiresPayment);
  }
  if (requiresPayment) {
    setStatus(
      "dashboard-status",
      "This service requires payment. The KryptNet payment link will be connected here when provided.",
      "neutral"
    );
  }
}

async function handleCheckoutPlan(plan) {
  const response = await fetch(apiPath("/api/payments/checkout"), {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({ plan }),
  });
  const payload = await response.json();
  if (!response.ok) {
    setStatus("dashboard-status", payload.detail || "Unable to prepare checkout.", "error");
    return;
  }
  const planName = payload.plan?.name || plan;
  const accessActive = payload.payment_access_status === "active";
  setStatus(
    "dashboard-status",
    accessActive
      ? `${planName} KryptNet debit/credit checkout link created. Paid access is active.`
      : `${planName} KryptNet debit/credit checkout link created. Complete checkout to activate paid access.`,
    accessActive ? "success" : "neutral"
  );
  if (payload.checkout_url) {
    window.open(payload.checkout_url, "_blank", "noopener");
  }
  await loadDashboard();
}

async function handleRequestCode(event) {
  event.preventDefault();
  const email = document.getElementById("email-input").value.trim();
  if (!email) {
    setStatus("auth-status", "Enter your email address before requesting a verification code.", "error");
    return;
  }
  state.email = email;

  setStatus("auth-status", "Sending verification code...", "neutral");
  try {
    const response = await fetch(apiPath("/api/auth/request-code"), {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify({ email }),
    });
    const payload = await response.json();

    if (!response.ok) {
      setStatus("auth-status", payload.detail || "Unable to send verification code.", "error");
      return;
    }

    const isConsoleDelivery = payload.delivery === "console";
    const message = isConsoleDelivery
      ? `Verification code generated for ${payload.email}. Local testing mode is active, so read the code from the server terminal to continue.`
      : `Verification code sent to ${payload.email}. Check your organizational inbox and spam folder.`;
    setStatus("verify-status", message, "success");
    showVerificationPage();
  } catch (error) {
    setStatus("auth-status", "Unable to contact the verification service. Please refresh the page and try again.", "error");
    return;
  }
}

async function handleVerifyCode(event) {
  event.preventDefault();
  const code = document.getElementById("code-input").value.trim();
  const email = document.getElementById("email-input").value.trim() || state.email;

  const response = await fetch(apiPath("/api/auth/verify"), {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({ email, code }),
  });
  const payload = await response.json();

  if (!response.ok) {
    setStatus("verify-status", payload.detail || "Verification failed.", "error");
    return;
  }

  setStatus(
    "verify-status",
    "Email verified. Choose a testing option to continue.",
    "success"
  );
  await loadDashboard(false, { showChoiceWhenAuthenticated: true });
}

async function handleCompleteRegistration(event) {
  event.preventDefault();
  const response = await fetch(apiPath("/api/auth/complete-registration"), {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({
      full_name: document.getElementById("register-name-input").value.trim(),
      job_title: document.getElementById("register-title-input").value.trim(),
      professional_role: document.getElementById("register-role-input").value.trim(),
      company_name: document.getElementById("register-company-input").value.trim(),
      company_address: document.getElementById("register-address-input").value.trim(),
      phone_number: document.getElementById("register-phone-input").value.trim(),
      testing_reason: document.getElementById("register-reason-input").value.trim(),
      safe_use_accepted: document.getElementById("register-safe-use-input").checked,
    }),
  });
  const payload = await response.json();
  if (!response.ok) {
    setStatus("registration-status", payload.detail || "Unable to complete registration.", "error");
    return;
  }
  setStatus("registration-status", "Registration completed. Choose a service to continue.", "success");
  await loadDashboard(false, { showChoiceWhenAuthenticated: true });
}

async function handleCreateScan(event) {
  event.preventDefault();
  const target = document.getElementById("target-input").value.trim();
  if (!target) {
    setStatus("dashboard-status", "Enter a domain name or IP address before starting the scan.", "error");
    return;
  }
  const assessment_mode = document.getElementById("assessment-mode-input").value;
  const scan_tier = document.getElementById("scan-tier-input").value;
  const authorizationConfirmed = document.getElementById("scan-authorization-input")?.checked === true;
  if (!authorizationConfirmed) {
    setStatus("dashboard-status", "Confirm that you own the target or have client/asset-owner permission before scanning.", "error");
    return;
  }
  const body = { target, assessment_mode, scan_tier, authorization_confirmed: authorizationConfirmed };
  if (assessment_mode === "ethical_pentesting") {
    body.pentest_depth = document.getElementById("pentest-depth-input").value;
    body.validation_mode = document.getElementById("validation-mode-input").value;
    body.vulnerability_focus = document
      .getElementById("vulnerability-focus-input")
      .value.split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    body.known_vulnerabilities = document.getElementById("known-vulnerabilities-input").value.trim() || null;
  }

  setStatus("dashboard-status", `Starting ${formatMode(assessment_mode)} for ${target}...`, "neutral");
  if (assessment_mode === "vulnerability_assessment" && scan_tier === "free_preview") {
    await runFreeScanFallback(body);
    return;
  }

  const response = await fetchWithTimeout(apiPath("/api/scans"), {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify(body),
  }, 30000);
  const payload = await response.json();

  if (!response.ok) {
    setStatus("dashboard-status", payload.detail || "Unable to launch assessment.", "error");
    return;
  }

  let deliveryNote = "";
  if (payload.status === "completed") {
    if (payload.report_email_sent_at) {
      deliveryNote = " PDF report emailed to your verified work address.";
    } else if (payload.report_email_error) {
      deliveryNote = ` Report created, but email delivery failed: ${payload.report_email_error}.`;
    } else if (payload.report_pdf_available) {
      deliveryNote = " PDF report is ready in the dashboard.";
    } else if (payload.scan_tier === "free_preview") {
      deliveryNote = " Free preview summary is available on the web interface.";
    }
  } else if (payload.status === "queued") {
    deliveryNote = " The scan is queued and will run in the background.";
  } else if (payload.status === "running") {
    deliveryNote = " The scan is running in the background.";
  }

  const successMessage = `${formatMode(payload.assessment_mode)} created for ${payload.target}. Current status: ${payload.status}.${deliveryNote}`;
  setStatus("dashboard-status", successMessage, "success");
  document.getElementById("scan-form").reset();
  selectAssessmentMode(state.assessmentMode);
  if (state.assessmentMode === "vulnerability_assessment") {
    selectScanTier(state.scanTier, { silent: true });
  }
  await loadDashboard(false);
  if (payload.status === "completed") {
    await loadReport(payload.id);
    setStatus("dashboard-status", `Scan completed successfully for ${payload.target}. Basic scan report is ready below.`, "success");
  } else {
    setStatus("dashboard-status", successMessage, "success");
  }
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 30000) {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    window.clearTimeout(timer);
  }
}

async function runFreeScanFallback(body) {
  let response;
  try {
    response = await fetchWithTimeout("/kryptscan/free-scan", {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify(body),
    }, 30000);
  } catch (error) {
    setStatus(
      "dashboard-status",
      "Free scan did not receive a response from the server. Please wait a moment and try again.",
      "error"
    );
    return;
  }

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    setStatus("dashboard-status", payload.detail || "Free scan could not be completed.", "error");
    return;
  }

  const scan = payload.scan;
  const report = payload.report;
  state.dashboard = payload.dashboard;
  state.activeScanId = scan.id;
  state.activeReport = report;
  renderDashboard(payload.dashboard);
  renderReport(report);
  showDashboardPage();
  document.getElementById("scan-form").reset();
  selectAssessmentMode("vulnerability_assessment");
  selectScanTier("free_preview", { silent: true });
  setStatus("dashboard-status", `Scan completed successfully for ${scan.target}. Basic scan report is ready below.`, "success");
}
async function handleLogout() {
  await fetch(apiPath("/api/auth/logout"), { method: "POST", headers: csrfHeaders() });
  if (state.refreshTimer) {
    window.clearTimeout(state.refreshTimer);
    state.refreshTimer = null;
  }
  state.dashboard = null;
  state.activeReport = null;
  state.activeScanId = null;
  showOnly("landing-page");
  setStatus("auth-status", "You have been logged out.", "neutral");
}

async function loadDashboard(showStatus = false, options = {}) {
  const response = await fetch(apiPath("/api/dashboard"));
  if (!response.ok) {
    const verified = routeParam("verified");
    const next = routeParam("next");
    if (verified && next === "choose-tool") {
      showToolChoicePage();
      return;
    }
    showOnly("landing-page");
    return;
  }

  const payload = await response.json();
  state.dashboard = payload;
  renderDashboard(payload);
  await loadScannerHealth();
  if (payload.user?.role === "client_viewer") {
    showDashboardPage();
    await loadClientPortal();
  } else if (options.showChoiceWhenAuthenticated) {
    showToolChoicePage();
  } else {
    showDashboardPage();
  }

  if (showStatus) {
    setStatus(
      "dashboard-status",
      `Connected to ${payload.organization.name} (${payload.organization.domain}).`,
      "neutral"
    );
  }

  const latestReport = payload.scans.find((scan) => scan.status === "completed");
  if (latestReport) {
    await loadReport(latestReport.id);
  }
  scheduleDashboardRefresh(payload);
}

function scheduleDashboardRefresh(payload) {
  if (state.refreshTimer) {
    window.clearTimeout(state.refreshTimer);
    state.refreshTimer = null;
  }
  const hasActiveScan = (payload.scans || []).some((scan) => ["queued", "running"].includes(scan.status));
  if (hasActiveScan) {
    state.refreshTimer = window.setTimeout(() => loadDashboard(false), 5000);
  }
}

async function loadScannerHealth() {
  const response = await fetch(apiPath("/api/scanner-health"));
  if (!response.ok) return;
  const payload = await response.json();
  renderScannerHealth(payload);
}

async function loadClientPortal() {
  const response = await fetch(apiPath("/api/client-portal"));
  const payload = await response.json();
  if (!response.ok) return;
  renderClientPortal(payload);
}

async function loadReport(scanId) {
  const response = await fetch(apiPath(`/api/reports/${scanId}`));
  const payload = await response.json();
  if (!response.ok) {
    setStatus("dashboard-status", payload.detail || "Report not ready yet.", "neutral");
    return;
  }

  state.activeReport = payload;
  state.activeScanId = scanId;
  document.getElementById("manual-finding-form").classList.remove("hidden");
  renderReport(payload);
}

async function handleAddManualFinding(event) {
  event.preventDefault();
  if (!state.activeScanId) {
    setStatus("dashboard-status", "Select a completed report before adding manual evidence.", "error");
    return;
  }
  const response = await fetch(apiPath(`/api/scans/${state.activeScanId}/manual-findings`), {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({
      title: document.getElementById("manual-title-input").value.trim(),
      severity: document.getElementById("manual-severity-input").value,
      category: document.getElementById("manual-category-input").value.trim(),
      evidence: document.getElementById("manual-evidence-input").value.trim(),
      remediation: document.getElementById("manual-remediation-input").value.trim(),
    }),
  });
  const payload = await response.json();
  if (!response.ok) {
    setStatus("dashboard-status", payload.detail || "Unable to add manual finding.", "error");
    return;
  }
  document.getElementById("manual-finding-form").reset();
  document.getElementById("manual-severity-input").value = "medium";
  setStatus("dashboard-status", `Manual finding added: ${payload.title}. Report regenerated.`, "success");
  await loadDashboard();
  await loadReport(state.activeScanId);
}

async function refreshScan(scanId) {
  const response = await fetch(apiPath(`/api/scans/${scanId}/refresh`), { method: "POST", headers: csrfHeaders() });
  const payload = await response.json();

  if (!response.ok) {
    setStatus("dashboard-status", payload.detail || "Unable to refresh scan.", "error");
    return;
  }

  setStatus(
    "dashboard-status",
    `Scan ${payload.id} refreshed. Current status: ${payload.status}.`,
    "neutral"
  );
  await loadDashboard();
  if (payload.status === "completed") {
    await loadReport(payload.id);
  }
}

function renderDashboard(payload) {
  document.getElementById("dashboard").classList.remove("hidden");
  document.getElementById(
    "dashboard-title"
  ).textContent = `${payload.organization.name} Security Command`;
  const clientOnly = payload.user?.role === "client_viewer";
  document.getElementById("scan-form").classList.toggle("hidden", clientOnly);
  document.getElementById("manual-finding-form").classList.toggle("hidden", clientOnly || !state.activeScanId);
  document.getElementById("client-portal-panel").classList.toggle("hidden", !clientOnly);
  selectAssessmentMode(state.assessmentMode);
  renderProfiles(payload.profiles || []);
  renderCommercialReadiness(payload);
  renderMembers(payload.members || []);
  renderPayments(payload.payments || []);
  renderAudit(payload.audit_events || []);
  updateServiceWorkspace();

  const statsGrid = document.getElementById("stats-grid");
  const toolchainGrid = document.getElementById("toolchain-grid");
  if (toolchainGrid) {
    toolchainGrid.innerHTML = (payload.toolchain || [])
      .map(
        (item) => `
          <article class="tool-card">
            <strong>${escapeHtml(item.category)}</strong>
            <div class="meta-line">${escapeHtml((item.tools || []).join(" - "))}</div>
            <p>${escapeHtml(item.purpose)}</p>
          </article>
        `
      )
      .join("");
  }
  const severity = payload.stats.latest_severity_counts || {};
  const cards = [
    ["Authorized Assets", payload.stats.authorized_assets ?? 0],
    ["Total Scans", payload.stats.total_scans ?? 0],
    ["Active Scans", payload.stats.active_scans ?? 0],
    ["Latest Risk Score", payload.stats.latest_risk_score ?? "N/A"],
    ["Critical Findings", severity.critical ?? 0],
    ["High Findings", severity.high ?? 0],
  ];
  statsGrid.innerHTML = cards
    .map(
      ([label, value]) => `
        <article class="stat-card">
          <div class="label">${label}</div>
          <div class="value">${value}</div>
        </article>
      `
    )
    .join("");
  renderScanProgress(payload.scans || []);

  const scanList = document.getElementById("scan-list");
  if (!payload.scans.length) {
    scanList.innerHTML =
      '<div class="check-card">No scans yet. Verify your domain email and launch the first assessment.</div>';
    return;
  }

  scanList.innerHTML = payload.scans
    .map(
      (scan) => `
        <article class="scan-card">
          <header>
            <div>
              <strong>${escapeHtml(scan.target)}</strong>
          <div class="meta-line">
            <span>${escapeHtml(scan.asset_type)}</span>
            <span>${escapeHtml(formatMode(scan.assessment_mode))}</span>
            <span>${escapeHtml(formatTier(scan.scan_tier))}</span>
            <span>${new Date(scan.created_at).toLocaleString()}</span>
          </div>
            </div>
            <span class="pill ${scan.status}">${scan.status}</span>
          </header>
          <div class="meta-line">
            <span>Risk score: ${scan.risk_score ?? "Pending"}</span>
            <span>Manual findings: ${scan.manual_finding_count ?? 0}</span>
            <span>${severityText(scan.severity_counts)}</span>
          </div>
          <div class="meta-line">
            <span>${escapeHtml(deliveryText(scan))}</span>
          </div>
          <div class="scan-actions">
            <button type="button" onclick="refreshScan(${scan.id})">Refresh</button>
            <button type="button" class="ghost" onclick="loadReport(${scan.id})">View Report</button>
            ${
              scan.report_pdf_available
                ? `<button type="button" class="ghost" onclick="downloadReport(${scan.id})">Download PDF</button>`
                : ""
            }
          </div>
        </article>
      `
    )
    .join("");
}

function scanProgressPercent(status) {
  if (status === "completed") return 100;
  if (status === "running") return 65;
  if (status === "queued") return 20;
  if (status === "failed") return 100;
  return 10;
}

function scanProgressLabel(scan) {
  if (scan.status === "completed") return "Scan complete successfully";
  if (scan.status === "running") return "Scanner is collecting evidence";
  if (scan.status === "queued") return "Scan accepted and preparing";
  if (scan.status === "failed") return "Scan failed";
  return "Scan status pending";
}

function renderScanProgress(scans) {
  const element = document.getElementById("scan-progress-grid");
  if (!element) return;
  const visibleScans = scans.slice(0, 3);
  if (!visibleScans.length) {
    element.innerHTML = "";
    return;
  }
  element.innerHTML = visibleScans
    .map((scan) => {
      const percent = scanProgressPercent(scan.status);
      const severity = scan.severity_counts || {};
      return `
        <article class="progress-card">
          <header>
            <div>
              <span class="progress-eyebrow">${escapeHtml(formatTier(scan.scan_tier))}</span>
              <strong>${escapeHtml(scan.target)}</strong>
            </div>
            <span class="pill ${scan.status}">${scan.status}</span>
          </header>
          <div class="progress-meter" aria-label="${percent}% complete">
            <span style="width: ${percent}%"></span>
          </div>
          <div class="progress-meta">
            <span>${percent}% complete</span>
            <span>${escapeHtml(scanProgressLabel(scan))}</span>
          </div>
          <div class="progress-report-row">
            <span>Risk ${scan.risk_score ?? "Pending"}</span>
            <span>Critical ${severity.critical ?? 0}</span>
            <span>High ${severity.high ?? 0}</span>
          </div>
        </article>
      `;
    })
    .join("");
}

function renderScannerHealth(payload) {
  const element = document.getElementById("scanner-health-grid");
  if (!element) return;
  const tools = payload.tools || [];
  element.innerHTML = `
    <article class="tool-card">
      <strong>Scanner Health</strong>
      <div class="meta-line">
        <span>${payload.available ?? 0} available</span>
        <span>${payload.missing ?? 0} missing</span>
      </div>
      <p>Install missing tools on the scanner server before relying on full production coverage.</p>
    </article>
    ${tools
      .map(
        (tool) => `
          <article class="tool-card">
            <strong>${escapeHtml(tool.name)}</strong>
            <div class="meta-line">
              <span>${escapeHtml(tool.category)}</span>
              <span class="pill ${tool.available ? "completed" : "warn"}">${tool.available ? "available" : "missing"}</span>
            </div>
            <p>${escapeHtml(tool.resolved_path || tool.configured_path || "Not configured")}</p>
          </article>
        `
      )
      .join("")}
  `;
}

function renderMembers(members) {
  const element = document.getElementById("member-list");
  if (!element) return;
  element.innerHTML = members.length
    ? members
        .map(
          (member) => `
            <article class="readiness-card">
              <strong>${escapeHtml(member.email)}</strong>
              <span class="pill completed">${escapeHtml(member.role)}</span>
              <p>${escapeHtml(member.full_name || "No display name")} - ${member.is_verified ? "verified" : "pending"}</p>
            </article>
          `
        )
        .join("")
    : "";
}

function renderClientPortal(payload) {
  const reportList = document.getElementById("client-report-list");
  const remediationList = document.getElementById("client-remediation-list");
  if (!reportList || !remediationList) return;
  reportList.innerHTML = payload.reports.length
    ? payload.reports
        .map(
          (report) => `
            <article class="scan-card">
              <header>
                <div>
                  <strong>${escapeHtml(report.target)}</strong>
                  <div class="meta-line">
                    <span>${escapeHtml(formatMode(report.assessment_mode))}</span>
                    <span>${escapeHtml(report.risk_band)} risk</span>
                    <span>Score ${report.risk_score}</span>
                  </div>
                </div>
                ${report.pdf_available ? `<button type="button" onclick="downloadReport(${report.scan_id})">PDF</button>` : ""}
              </header>
            </article>
          `
        )
        .join("")
    : `<div class="check-card">No completed reports yet.</div>`;
  remediationList.innerHTML = payload.remediation_queue.length
    ? payload.remediation_queue
        .map(
          (item) => `
            <article class="check-card">
              <div class="meta-line">
                <strong>${escapeHtml(item.title)}</strong>
                <span class="pill ${String(item.priority).toLowerCase()}">${escapeHtml(item.priority)}</span>
              </div>
              <p>${escapeHtml(item.target)}: ${escapeHtml(item.action)}</p>
            </article>
          `
        )
        .join("")
    : `<div class="check-card">No remediation items yet.</div>`;
}

function renderCommercialReadiness(payload) {
  const element = document.getElementById("commercial-readiness");
  if (!element || !payload) return;
  const paymentActive = payload.entitlement?.status === "active";
  const paidRequired =
    state.assessmentMode === "ethical_pentesting" || state.scanTier === "full_scan";
  element.innerHTML = `
    <article class="readiness-card">
      <strong>Payment</strong>
      <span class="pill ${!paidRequired || paymentActive ? "completed" : "warn"}">${!paidRequired ? "free preview" : paymentActive ? "paid" : "required"}</span>
      <p>${
        !paidRequired
          ? "Free vulnerability scan runs partial checks and displays a summary in the web interface. PDF delivery is available with the paid full scan."
          : paymentActive
            ? `Paid package ${escapeHtml(payload.entitlement.plan)} access is valid until ${new Date(payload.entitlement.expires_at).toLocaleDateString()}.`
            : "Complete a one-time payment before launching full vulnerability scans or ethical pen-testing."
      }</p>
      ${!paidRequired || paymentActive ? "" : `<p>Choose one service package. Debit and credit card details stay inside KryptNet checkout.</p>`}
    </article>
  `;
}

function renderPayments(payments) {
  const element = document.getElementById("payment-list");
  if (!element) return;
  element.innerHTML = payments.length
    ? payments
        .map(
          (payment) => `
            <article class="readiness-card">
              <strong>${escapeHtml(payment.plan)} - ${(payment.amount_cents / 100).toLocaleString(undefined, { style: "currency", currency: payment.currency })}</strong>
              <span class="pill completed">${escapeHtml(payment.status)}</span>
              <p>${escapeHtml(payment.payment_method)} - ${escapeHtml(payment.provider_reference)}</p>
            </article>
          `
        )
        .join("")
    : "";
}

function renderProfiles(profiles) {
  const element = document.getElementById("profile-grid");
  if (!element) return;
  element.innerHTML = profiles
    .map(
      (profile) => `
        <article class="profile-card">
          <strong>${escapeHtml(profile.name)}</strong>
          <div class="meta-line">${escapeHtml((profile.categories || []).join(" - "))}</div>
          <p>${escapeHtml(profile.summary)}</p>
        </article>
      `
    )
    .join("");
}

function renderAudit(events) {
  const element = document.getElementById("audit-list");
  if (!element) return;
  element.innerHTML = events.length
    ? events
        .map(
          (event) => `
            <article class="check-card">
              <div class="meta-line">
                <strong>${escapeHtml(event.action)}</strong>
                <span>${new Date(event.created_at).toLocaleString()}</span>
              </div>
              <p>${escapeHtml(JSON.stringify(event.details || {}))}</p>
            </article>
          `
        )
        .join("")
    : `<div class="check-card">No audit events yet.</div>`;
}

function renderReport(report) {
  const riskBand = document.getElementById("report-risk-band");
  riskBand.textContent = `${report.risk_band} Risk`;
  riskBand.className = `risk-band ${String(report.risk_band).toLowerCase()}`;
  const activeScan = state.dashboard?.scans?.find((scan) => scan.id === state.activeScanId);
  document
    .getElementById("report-download-button")
    .classList.toggle("hidden", !activeScan?.report_pdf_available);
  document.getElementById("executive-summary").textContent = report.executive_summary;

  renderBars("severity-chart", [
    { label: "Critical", value: report.severity_counts.critical, color: "#d94b37" },
    { label: "High", value: report.severity_counts.high, color: "#ff7a45" },
    { label: "Medium", value: report.severity_counts.medium, color: "#efb53d" },
    { label: "Low", value: report.severity_counts.low, color: "#2ab57f" },
    { label: "Info", value: report.severity_counts.info, color: "#2f63ff" },
  ]);
  renderBars(
    "services-chart",
    report.top_services.map((item) => ({ ...item, color: "#2f63ff" }))
  );
  renderBars(
    "categories-chart",
    report.top_categories.map((item) => ({ ...item, color: "#ff7a45" }))
  );
  renderTrend("trend-chart", report.trend);

  document.getElementById("checks-list").innerHTML = report.compliance_checks
    .map(
      (check) => `
        <article class="check-card">
          <div class="meta-line">
            <strong>${escapeHtml(check.name)}</strong>
            <span class="pill ${check.status}">${check.status}</span>
          </div>
          <p>${escapeHtml(check.detail)}</p>
        </article>
      `
    )
    .join("");

  document.getElementById("remediation-list").innerHTML = report.remediation_plan
    .map(
      (item) => `
        <article class="check-card">
          <div class="meta-line">
            <strong>${escapeHtml(item.title)}</strong>
            <span class="pill ${item.priority.toLowerCase()}">${escapeHtml(item.priority)}</span>
          </div>
          <p>${escapeHtml(item.action)}</p>
        </article>
      `
    )
    .join("");

  document.getElementById("findings-list").innerHTML = report.findings
    .map(
      (finding) => `
        <article class="finding-card">
          <header>
            <div>
              <strong>${escapeHtml(finding.title)}</strong>
              <div class="meta-line">
                <span>${escapeHtml(finding.category)}</span>
                <span>${escapeHtml(finding.host)}</span>
                <span>${escapeHtml(finding.port || "n/a")}</span>
              </div>
            </div>
            <span class="pill ${finding.severity}">${escapeHtml(finding.severity)}</span>
          </header>
          <div class="meta-line">
            <span>CVSS ${finding.cvss}</span>
            <span>${escapeHtml(finding.cve || "No CVE supplied")}</span>
          </div>
          <p>${escapeHtml(finding.description)}</p>
          <p><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</p>
        </article>
      `
    )
    .join("");
}

function renderBars(elementId, items) {
  const element = document.getElementById(elementId);
  const max = Math.max(...items.map((item) => Number(item.value || 0)), 1);
  element.innerHTML = items
    .map((item) => {
      const width = Math.max(8, (Number(item.value || 0) / max) * 100);
      return `
        <div class="bar-row">
          <div class="bar-meta">
            <span>${escapeHtml(item.label)}</span>
            <span>${item.value}</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width: ${width}%; background: ${item.color || "#4fd1c5"};"></div>
          </div>
        </div>
      `;
    })
    .join("");
}

function renderTrend(elementId, points) {
  const element = document.getElementById(elementId);
  const values = points.map((point) => Number(point.value || 0));
  const max = Math.max(...values, 1);
  const width = 360;
  const height = 160;
  const padding = 20;
  const step = (width - padding * 2) / Math.max(points.length - 1, 1);

  const polyline = points
    .map((point, index) => {
      const x = padding + step * index;
      const y = height - padding - ((Number(point.value || 0) / max) * (height - padding * 2));
      return `${x},${y}`;
    })
    .join(" ");

  element.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" fill="none" aria-label="Risk trend">
      <path d="M ${padding} ${height - padding} H ${width - padding}" stroke="rgba(20,32,51,0.12)" />
      <polyline points="${polyline}" stroke="#2f63ff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round" />
      ${points
        .map((point, index) => {
          const x = padding + step * index;
          const y = height - padding - ((Number(point.value || 0) / max) * (height - padding * 2));
          return `<circle cx="${x}" cy="${y}" r="5" fill="#ff7a45" />`;
        })
        .join("")}
    </svg>
    <div class="trend-labels">
      ${points.map((point) => `<span>${escapeHtml(point.label)}</span>`).join("")}
    </div>
  `;
}

function setStatus(elementId, message, tone = "neutral") {
  const element = document.getElementById(elementId);
  element.textContent = message;
  element.className = `status-card ${tone}`;
  element.classList.remove("hidden");
}

function severityText(counts) {
  if (!counts) {
    return "Report pending";
  }
  return `C:${counts.critical} H:${counts.high} M:${counts.medium} L:${counts.low}`;
}

function deliveryText(scan) {
  if (scan.report_email_sent_at) {
    return `PDF emailed ${new Date(scan.report_email_sent_at).toLocaleString()}`;
  }
  if (scan.report_email_error) {
    return `Email delivery error: ${scan.report_email_error}`;
  }
  if (scan.report_pdf_available) {
    return "PDF ready for download";
  }
  if (scan.scan_tier === "free_preview") {
    return "Web summary only";
  }
  return "PDF pending";
}

function formatMode(mode) {
  return mode === "ethical_pentesting" || mode === "authorized_pentest" ? "Ethical Pen-Testing" : "Vulnerability Assessment";
}

function formatTier(tier) {
  return tier === "free_preview" ? "Free Scan" : "Full Scan";
}

function downloadReport(scanId) {
  window.location.assign(apiPath(`/api/reports/${scanId}/pdf`));
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

window.refreshScan = refreshScan;
window.loadReport = loadReport;
window.downloadReport = downloadReport;
