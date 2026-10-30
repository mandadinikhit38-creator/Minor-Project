(() => {
  "use strict";

  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);

  function renderResult(tool, result) {
    const lines = [];
    if (tool === "ssl") {
      lines.push(result.valid ? "Certificate verified" : "Certificate could not be verified");
      if (result.issuer) lines.push(`Issuer: ${result.issuer}`);
      if (result.expires_on) lines.push(`Expires: ${result.expires_on}`);
      if (result.error) lines.push(result.error);
    } else if (tool === "dns") {
      lines.push(`Resolved ${result.domain}:`);
      lines.push(...result.records.map((record) => `${record.type}: ${record.value}`));
    } else if (tool === "expand") {
      lines.push(`Final URL: ${result.final_url}`);
      lines.push(...result.redirect_chain.map((url, index) => `${index + 1}. ${url}`));
    } else if (tool === "age") {
      lines.push(result.status === "available"
        ? `${result.domain}: ${result.age_days} days old${result.registered_on ? ` (registered ${result.registered_on})` : ""}`
        : result.status === "not_applicable"
          ? "Registration age is not available for IP addresses."
          : `Registration data is unavailable for ${result.domain}.`);
    } else if (tool === "ip-reputation") {
      lines.push(result.status === "checked"
        ? `${result.verdict} · ${result.malicious} malicious, ${result.suspicious} suspicious, ${result.harmless} harmless reports.`
        : result.message || "IP reputation is unavailable.");
    } else if (tool === "scam-check") {
      lines.push(`${result.verdict} · risk score ${result.risk_score}/${result.max_score}`);
      lines.push(...(result.checks || []).map((check) => check.title));
    }
    return lines.map((line) => `<div>${escapeHtml(line)}</div>`).join("");
  }

  document.querySelectorAll(".tool-form").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const tool = form.dataset.tool;
      const value = form.querySelector('[name="value"]').value.trim();
      const output = form.parentElement.querySelector(".tool-output");
      const button = form.querySelector("button");
      output.textContent = "Checking…";
      button.disabled = true;
      try {
        const response = await fetch(`/api/tools/${encodeURIComponent(tool)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ value }),
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.detail || `Check failed (${response.status}).`);
        output.innerHTML = renderResult(tool, result);
      } catch (error) {
        output.textContent = error instanceof TypeError
          ? "Could not reach PhishLens. Check that the scanner server is running."
          : error.message;
      } finally {
        button.disabled = false;
      }
    });
  });

  const passwordInput = document.querySelector("#password-check-input");
  const passwordOutput = document.querySelector("#password-check-output");
  const passwordMeter = document.querySelector(".password-meter");
  const passwordVisibility = document.querySelector("#password-visibility");
  const commonPasswords = new Set([
    "123456", "123456789", "12345678", "password", "password1", "qwerty",
    "qwerty123", "admin", "letmein", "welcome", "iloveyou", "abc123",
  ]);
  function assessPassword(password) {
    if (!password) return { score: 0, message: "Password checks run only in this browser." };
    const feedback = [];
    const lower = password.toLowerCase();
    if (commonPasswords.has(lower)) {
      return { score: 0, message: "Very weak: this is a commonly used password. Choose a unique passphrase." };
    }
    if (password.length < 12) feedback.push("Use at least 12 characters");
    const groups = [
      /[a-z]/.test(password), /[A-Z]/.test(password),
      /\d/.test(password), /[^A-Za-z0-9]/.test(password),
    ].filter(Boolean).length;
    if (groups < 3) feedback.push("mix several character types");
    const repeated = /(.)\1{3,}/.test(password);
    const sequential = /(?:0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|ijkl|jklm|klmn|lmno|mnop|nopq|opqr|pqrs|qrst|rstu|stuv|tuvw|uvwx|vwxy|wxyz)/i.test(password);
    if (repeated || sequential) feedback.push("avoid repeated or sequential patterns");
    const pool = (/[a-z]/.test(password) ? 26 : 0)
      + (/[A-Z]/.test(password) ? 26 : 0)
      + (/\d/.test(password) ? 10 : 0)
      + (/[^A-Za-z0-9]/.test(password) ? 33 : 0);
    let estimatedBits = password.length * Math.log2(Math.max(pool, 1));
    if (repeated) estimatedBits *= 0.45;
    if (sequential) estimatedBits *= 0.7;
    let score = estimatedBits < 28 ? 0 : estimatedBits < 36 ? 1 : estimatedBits < 60 ? 2 : estimatedBits < 80 ? 3 : 4;
    if (feedback.length) score = Math.min(score, feedback.length > 1 ? 1 : 2);
    const labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];
    return {
      score,
      message: `${labels[score]} local estimate.${feedback.length ? ` ${feedback.join("; ")}.` : " Use a unique password for every account."}`,
    };
  }
  function updatePasswordCheck() {
    const result = assessPassword(passwordInput.value);
    passwordOutput.textContent = result.message;
    passwordMeter.setAttribute("aria-valuenow", String(result.score));
    passwordMeter.dataset.strength = String(result.score);
  }
  passwordInput.addEventListener("input", updatePasswordCheck);
  passwordVisibility.addEventListener("click", () => {
    const reveal = passwordInput.type === "password";
    passwordInput.type = reveal ? "text" : "password";
    passwordVisibility.textContent = reveal ? "Hide" : "Show";
    passwordVisibility.setAttribute("aria-label", reveal ? "Hide password" : "Show password");
  });

  const qrGenerateForm = document.querySelector("#qr-generate-form");
  const qrContentInput = document.querySelector("#qr-content");
  const qrGeneratedOutput = document.querySelector("#qr-generated-output");
  qrGenerateForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = qrGenerateForm.querySelector("button");
    const value = qrContentInput.value;
    if (!value.trim() || new TextEncoder().encode(value).length > 2048) {
      qrGeneratedOutput.textContent = "Enter QR content of 1–2,048 UTF-8 bytes.";
      return;
    }
    if (!window.phishlensQr) {
      qrGeneratedOutput.textContent = "The local QR tools did not load. Refresh this page and try again.";
      return;
    }
    button.disabled = true;
    qrGeneratedOutput.textContent = "Generating QR code in this browser…";
    try {
      const imageUrl = await window.phishlensQr.generate(value);
      qrGeneratedOutput.innerHTML = `<img class="qr-generated-image" alt="Generated QR code" src="${imageUrl}"><a class="qr-download" download="phishlens-qr.png" href="${imageUrl}">Download QR image</a>`;
    } catch (error) {
      qrGeneratedOutput.textContent = error.message || "Could not create that QR code.";
    } finally {
      button.disabled = false;
    }
  });

  const qrImageInput = document.querySelector("#qr-image-input");
  const qrImageReadButton = document.querySelector("#qr-image-read");
  const qrReadOutput = document.querySelector("#qr-read-output");
  function decodeQRCanvas(canvas) {
    if (!window.phishlensQr) {
      qrReadOutput.textContent = "The local QR tools did not load. Refresh this page and try again.";
      return;
    }
    const image = canvas.getContext("2d").getImageData(0, 0, canvas.width, canvas.height);
    const result = window.phishlensQr.decode(image.data, image.width, image.height);
    if (!result) {
      qrReadOutput.textContent = "No QR code was found in that image.";
      return;
    }
    qrReadOutput.innerHTML = `<strong>Decoded content (not opened):</strong><div class="qr-decoded-value">${escapeHtml(result.data)}</div><div>Treat QR content as untrusted. It has not been checked for safety.</div>`;
  }
  async function decodeQRFile(file) {
    if (!["image/png", "image/jpeg", "image/webp"].includes(file.type) || file.size > 5_000_000) {
      qrReadOutput.textContent = "Choose a PNG, JPEG, or WebP image no larger than 5 MB.";
      return;
    }
    qrReadOutput.textContent = "Reading QR image in this browser…";
    try {
      const image = await createImageBitmap(file);
      if (image.width * image.height > 16_000_000) {
        image.close();
        throw new Error("Image dimensions are too large to scan.");
      }
      cameraCanvas.width = image.width;
      cameraCanvas.height = image.height;
      cameraCanvas.getContext("2d").drawImage(image, 0, 0);
      image.close();
      decodeQRCanvas(cameraCanvas);
    } catch (error) {
      qrReadOutput.textContent = error.message || "The selected image could not be read.";
    }
  }
  qrImageInput.addEventListener("change", () => {
    const file = qrImageInput.files[0];
    qrImageReadButton.disabled = !file;
  });
  qrImageReadButton.addEventListener("click", async () => {
    const file = qrImageInput.files[0];
    if (!file) return;
    qrImageReadButton.disabled = true;
    try {
      await decodeQRFile(file);
    } finally {
      qrImageReadButton.disabled = !qrImageInput.files[0];
    }
  });

  const cameraStartButton = document.querySelector("#qr-camera-start");
  const cameraCaptureButton = document.querySelector("#qr-camera-capture");
  const cameraStopButton = document.querySelector("#qr-camera-stop");
  const cameraPreview = document.querySelector("#qr-camera-preview");
  const cameraCanvas = document.querySelector("#qr-camera-canvas");
  let cameraStream = null;
  cameraStartButton.addEventListener("click", async () => {
    if (!navigator.mediaDevices?.getUserMedia) {
      qrReadOutput.textContent = "Camera scanning is not available in this browser. Upload a QR image instead.";
      return;
    }
    cameraStartButton.disabled = true;
    try {
      cameraStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: "environment" } }, audio: false });
      cameraPreview.srcObject = cameraStream;
      cameraPreview.classList.remove("hidden");
      await cameraPreview.play();
      cameraCaptureButton.disabled = false;
      cameraStopButton.disabled = false;
      qrReadOutput.textContent = "Camera ready. Point it at a QR code and capture a frame.";
    } catch {
      cameraStartButton.disabled = false;
      qrReadOutput.textContent = "Could not start the camera. Check browser permissions or upload an image instead.";
    }
  });
  function stopCamera() {
    if (cameraStream) cameraStream.getTracks().forEach((track) => track.stop());
    cameraStream = null;
    cameraPreview.srcObject = null;
    cameraPreview.classList.add("hidden");
    cameraStartButton.disabled = false;
    cameraCaptureButton.disabled = true;
    cameraStopButton.disabled = true;
  }
  cameraStopButton.addEventListener("click", stopCamera);
  cameraCaptureButton.addEventListener("click", () => {
    if (!cameraPreview.videoWidth || !cameraPreview.videoHeight) return;
    if (cameraPreview.videoWidth * cameraPreview.videoHeight > 16_000_000) {
      qrReadOutput.textContent = "Camera frame dimensions are too large to scan.";
      return;
    }
    cameraCanvas.width = cameraPreview.videoWidth;
    cameraCanvas.height = cameraPreview.videoHeight;
    cameraCanvas.getContext("2d").drawImage(cameraPreview, 0, 0);
    try {
      decodeQRCanvas(cameraCanvas);
    } catch (error) {
      qrReadOutput.textContent = error.message || "Could not read a QR code from this frame.";
    }
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopCamera();
  });
  window.addEventListener("pagehide", stopCamera);

  const themeToggle = document.querySelector("#theme-toggle");
  const themeIcon = document.querySelector("#theme-icon");
  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("phishlens.theme", theme);
    } catch {
      // Keep the selected theme for this page even if browser storage is disabled.
    }
    themeIcon.textContent = theme === "light" ? "☾" : "☼";
  }
  themeToggle.addEventListener("click", () => {
    setTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
  });
  try {
    if (localStorage.getItem("phishlens.theme") === "light") setTheme("light");
  } catch {
    // Use the default dark theme when browser storage is unavailable.
  }
})();
