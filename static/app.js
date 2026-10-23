(() => {
  "use strict";
  const form = document.querySelector("#scan-form");
  const input = document.querySelector("#url-input");
  const button = document.querySelector("#scan-button");
  const message = document.querySelector("#form-message");
  const resultSection = document.querySelector("#result-section");
  const historyList = document.querySelector("#history-list");
  const clearHistoryButton = document.querySelector("#clear-history");
  const toast = document.querySelector("#toast");
  const HISTORY_KEY = "phishlens.history.v1";
  let scans = loadHistory();
  let toastTimer;

  function storageGet(key) {
    try { return localStorage.getItem(key); } catch { return null; }
  }
  function storageSet(key, value) {
    try { localStorage.setItem(key, value); return true; } catch { return false; }
  }
  function storageRemove(key) {
    try { localStorage.removeItem(key); return true; } catch { return false; }
  }
  function loadHistory() {
    try {
      const value = JSON.parse(storageGet(HISTORY_KEY) || "[]");
      if (!Array.isArray(value)) return [];
      return value.slice(0, 8).map((item) => {
        if (!item) return item;
        const storedScore = Number(item.risk_score);
        if (!Number.isFinite(storedScore)) return item;
        const riskScore = storedScore > 10
          ? Math.max(1, Math.min(10, Math.round(storedScore / 10 * 10) / 10))
          : storedScore;
        const verdict = riskScore >= 6 ? "Phishing" : riskScore > 3 ? "Suspicious" : "Safe";
        return {
          ...item,
          risk_score: riskScore,
          verdict,
          result: item.result ? {
            ...item.result,
            risk_score: riskScore,
            max_score: 10,
            verdict,
          } : item.result,
        };
      });
    } catch {
      return [];
    }
  }
  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[char]);
  }
  function showToast(text) {
    toast.textContent = text;
    toast.classList.add("visible");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("visible"), 2600);
  }
  function verdictClass(verdict) { return verdict.toLowerCase(); }
  function displayTime(value) {
    try { return new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }); }
    catch { return "Just now"; }
  }
  function renderHistory() {
    clearHistoryButton.classList.toggle("hidden", scans.length === 0);
    if (!scans.length) {
      historyList.innerHTML = '<div class="empty-history"><span>◷</span><p>Your recent scans will appear here.</p></div>';
      return;
    }
    historyList.innerHTML = scans.map((item, index) => `
      <button type="button" class="history-row" data-history-index="${index}">
        <span class="history-dot" style="background:var(--${item.verdict === "Safe" ? "green" : item.verdict === "Phishing" ? "red" : "yellow"})"></span>
        <span class="history-url">${escapeHtml(item.url)}</span>
        <span class="history-verdict" style="color:var(--${item.verdict === "Safe" ? "green" : item.verdict === "Phishing" ? "red" : "yellow"})">${escapeHtml(item.verdict)}</span>
        <span class="history-score">${Number(item.risk_score)}/10</span>
        <span class="history-date">${escapeHtml(displayTime(item.scanned_at))}</span>
      </button>`).join("");
    historyList.querySelectorAll("[data-history-index]").forEach((row) => row.addEventListener("click", () => {
      const item = scans[Number(row.dataset.historyIndex)];
      if (item?.result) renderResult(item.result);
    }));
  }
  function detailCell(label, value, sub = "") {
    return `<div class="detail-cell"><div class="detail-label">${escapeHtml(label)}</div><div class="detail-value">${escapeHtml(value || "Not available")}</div>${sub ? `<div class="detail-sub">${escapeHtml(sub)}</div>` : ""}</div>`;
  }
  function renderResult(data) {
    const details = data.details || {};
    const domain = details.domain || {};
    const page = details.page || {};
    const model = details.model || {};
    const xgboostModel = details.xgboost_model || {};
    const checks = data.all_checks || data.checks || [];
    const triggered = new Set((data.checks || []).map((check) => check.name));
    const color = data.verdict === "Safe" ? "var(--green)" : data.verdict === "Phishing" ? "var(--red)" : "var(--yellow)";
    const radius = 45;
    const circumference = 2 * Math.PI * radius;
    const maxScore = Number(data.max_score) || 10;
    const score = Math.max(1, Math.min(maxScore, Number(data.risk_score)));
    const offset = circumference * (1 - score / maxScore);
    const checkList = checks.filter((check) => triggered.has(check.name));
    const ssl = domain.ssl || {};
    const registration = domain.registered_on ? `Registered ${domain.registered_on}` : "Registration date unavailable";
    const modelValue = model.prediction === "phishing" ? "Phishing pattern" : model.prediction === "benign" ? "No phishing pattern" : model.status === "not_trained" ? "Not trained" : model.status === "dependency_missing" ? "PyTorch not installed" : model.status === "error" ? "Model error" : "Unavailable";
    const modelSub = model.phishing_probability == null
      ? (model.error || "Heuristic checks continue without the model.")
      : `${Math.round(model.confidence * 100)}% confidence · ${Math.round(model.phishing_probability * 100)}% phishing probability · threshold ${Math.round(model.threshold * 100)}%`;
    const xgboostValue = xgboostModel.prediction === "phishing" ? "Phishing pattern" : xgboostModel.prediction === "benign" ? "No phishing pattern" : xgboostModel.status === "not_trained" ? "Not trained" : xgboostModel.status === "dependency_missing" ? "XGBoost not installed" : xgboostModel.status === "error" ? "Model error" : "Unavailable";
    const xgboostSub = xgboostModel.phishing_probability == null
      ? (xgboostModel.error || "Heuristic checks continue without this optional model.")
      : `${Math.round(xgboostModel.confidence * 100)}% confidence · ${Math.round(xgboostModel.phishing_probability * 100)}% phishing probability · threshold ${Math.round(xgboostModel.threshold * 100)}%`;
    const redirects = (page.redirect_chain || [data.url]).map((url) => `<div class="redirect-step">${escapeHtml(url)}</div>`).join("");
    const feedNames = { local_list: "Local list", google_safe_browsing: "Google Safe Browsing", virustotal: "VirusTotal" };
    const feeds = Object.entries(details.threat_feeds || {}).map(([name, feed]) => {
      const state = feed.matched ? "match" : feed.status === "checked" ? "checked" : "";
      const status = feed.matched ? "Threat found" : feed.status === "checked" ? "No match" : feed.status === "not_configured" ? "Not configured" : "Unavailable";
      return `<span class="feed-item"><i class="feed-dot ${state}"></i>${escapeHtml(feedNames[name] || name)}: ${escapeHtml(status)}</span>`;
    }).join("");
    resultSection.innerHTML = `
      <article class="result-card">
        <div class="result-top">
          <div class="result-url-wrap"><div class="result-label">Scan report</div><div class="result-url">${escapeHtml(data.url)}</div><div class="result-stamp">Scanned ${escapeHtml(displayTime(data.scanned_at))}</div></div>
          <div class="verdict-pill ${verdictClass(data.verdict)}"><span>●</span>${escapeHtml(data.verdict)}</div>
        </div>
        <div class="result-main">
          <div class="score-panel">
            <div class="score-gauge"><svg viewBox="0 0 100 100" aria-label="Risk score ${score} out of ${maxScore}"><circle class="gauge-track" cx="50" cy="50" r="${radius}"></circle><circle class="gauge-value" cx="50" cy="50" r="${radius}" style="stroke:${color};stroke-dasharray:${circumference};stroke-dashoffset:${offset}"></circle></svg><div class="score-number">${score}<small>/ ${maxScore}</small></div></div>
            <div><div class="score-caption">${data.verdict === "Safe" ? "Low risk detected" : data.verdict === "Phishing" ? "High risk detected" : "Use caution"}</div><div class="score-note">Suspicious above 3 · Phishing at 6. Estimate only, not a guarantee.</div></div>
          </div>
          <div class="checks-panel"><h3>Triggered checks <span style="color:var(--muted);font-weight:400">(${checkList.length})</span></h3>
            ${checkList.length ? `<div class="check-list">${checkList.map((check) => `<div class="check-item triggered"><span class="check-icon">!</span><div><div class="check-title">${escapeHtml(check.title)}</div><div class="check-copy">${escapeHtml(check.explanation)}</div></div></div>`).join("")}</div>` : '<div class="empty-checks">✓ No high-risk signals were detected by this scan.</div>'}
          </div>
        </div>
        <div class="details-wrap"><h3 class="details-title">Technical details</h3><div class="details-grid">
          ${detailCell("Domain", domain.domain, domain.age_days == null ? registration : `${domain.age_days} days old · ${registration}`)}
          ${detailCell("HTTPS certificate", ssl.valid === true ? "Valid" : ssl.valid === false ? "Invalid / unavailable" : "Not checked", ssl.issuer || (ssl.expires_on ? `Expires ${ssl.expires_on}` : ""))}
          ${detailCell("DNS / hosting", domain.dns?.ip || "Unavailable", domain.dns?.status === "resolved" ? "Public IP address" : domain.dns?.status)}
          ${detailCell("Page title", page.title || (page.error ? "Page could not be inspected" : "No title found"))}
          ${detailCell("Login form", page.login_form == null ? "Not inspected" : page.login_form ? "Password field found" : "No password field found")}
          ${detailCell("External links", page.external_links == null ? "Not inspected" : `${page.external_links} external domains`, page.hidden_iframes ? `${page.hidden_iframes} hidden iframe(s)` : "No hidden iframes detected")}
          ${detailCell("Deep-learning URL model", modelValue, modelSub)}
          ${detailCell("XGBoost URL model", xgboostValue, xgboostSub)}
          <div class="detail-cell"><div class="detail-label">Redirect chain</div><div class="detail-value redirect-list">${redirects}</div></div>
        </div></div>
        ${feeds ? `<div class="feed-row">${feeds}</div>` : ""}
        <div class="result-actions"><button type="button" class="report-button" id="report-button">↗ Report this URL to Google</button></div>
      </article>`;
    resultSection.classList.remove("hidden");
    resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
    document.querySelector("#report-button").addEventListener("click", () => {
      window.open(`https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(data.url)}`, "_blank", "noopener,noreferrer");
    });
  }
  function setLoading(isLoading) {
    button.disabled = isLoading;
    button.querySelector(".button-label").textContent = isLoading ? "Scanning…" : "Scan URL";
    button.querySelector(".button-arrow").textContent = isLoading ? "◌" : "→";
  }
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const url = input.value.trim();
    message.textContent = "";
    if (!url) { message.textContent = "Paste a URL to get started."; input.focus(); return; }
    if (url.length > 2048) { message.textContent = "That URL is too long. Please enter a shorter URL."; return; }
    setLoading(true);
    try {
      const response = await fetch("/api/scan", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || `Scan failed (${response.status}). Try again.`);
      renderResult(result);
      if (Number(result.risk_score) > 5) {
        window.alert(`Warning: this URL has a high risk score of ${result.risk_score}/10 (${result.verdict}).`);
      }
      scans = [{ url: result.url, verdict: result.verdict, risk_score: result.risk_score, scanned_at: result.scanned_at, result }, ...scans.filter((item) => item.url !== result.url)].slice(0, 8);
      if (!storageSet(HISTORY_KEY, JSON.stringify(scans))) showToast("Scan complete. Browser storage is unavailable.");
      renderHistory();
    } catch (error) {
      message.textContent = error instanceof TypeError ? "Could not reach the scanner. Check your connection and try again." : error.message;
    } finally {
      setLoading(false);
    }
  });
  clearHistoryButton.addEventListener("click", () => {
    scans = [];
    storageRemove(HISTORY_KEY);
    renderHistory();
    showToast("Scan history cleared.");
  });
  document.querySelector("#theme-toggle").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    storageSet("phishlens.theme", next);
    document.querySelector("#theme-icon").textContent = next === "light" ? "☾" : "☼";
  });
  const savedTheme = storageGet("phishlens.theme");
  if (savedTheme === "light") {
    document.documentElement.dataset.theme = savedTheme;
    document.querySelector("#theme-icon").textContent = "☾";
  }
  renderHistory();
})();
