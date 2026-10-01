const API_BASE_URL = "https://cyber-security-assistant-six.vercel.app";
const urlForm = document.querySelector("#url-form");
const scanForm = document.querySelector("#scan-form");
const urlResult = document.querySelector("#url-result");
const scanResult = document.querySelector("#scan-result");
const screenshotForm = document.querySelector("#screenshot-form");
const screenshotInput = document.querySelector("#screenshot-input");
const screenshotResult = document.querySelector("#screenshot-result");
const screenshotPreview = document.querySelector("#screenshot-preview");
const MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024;
const MAX_SCREENSHOT_PIXELS = 25000000;
let screenshotObjectUrl = null;

function setLoading(button, loading, label) {
  button.disabled = loading;
  button.querySelector("span").textContent = loading ? "Checking..." : label;
}

async function postJson(path, payload) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch {
    throw new Error("Could not reach the API. Start FastAPI at http://127.0.0.1:8000 and try again.");
  }

  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("The server returned an unreadable response. Please try again.");
  }
  if (!response.ok) {
    const detail = typeof data.detail === "string" ? data.detail : "Please review the information and try again.";
    throw new Error(detail);
  }
  return data;
}

function createList(title, items, className) {
  const section = document.createElement("div");
  const heading = document.createElement("strong");
  heading.textContent = title;
  section.append(heading);
  if (!items.length) {
    const empty = document.createElement("p");
    empty.className = "scan-caption";
    empty.textContent = title === "Warnings" ? "No obvious indicators detected." : "No additional recommendations.";
    section.append(empty);
    return section;
  }
  const list = document.createElement("ul");
  list.className = `result-list ${className}`;
  for (const item of items) {
    const entry = document.createElement("li");
    entry.textContent = item;
    list.append(entry);
  }
  section.append(list);
  return section;
}

function renderUrlResult(result) {
  urlResult.className = "result-panel";
  urlResult.replaceChildren();

  const header = document.createElement("div");
  header.className = "result-header";
  const title = document.createElement("h3");
  title.textContent = result.url;
  const badge = document.createElement("span");
  const riskClass = result.risk_level.toLowerCase();
  badge.className = `risk-badge risk-${riskClass}`;
  badge.textContent = `${result.risk_level} RISK`;
  header.append(title, badge);

  const summary = document.createElement("p");
  summary.className = "result-summary";
  summary.textContent = result.summary;
  const facts = document.createElement("div");
  facts.className = "result-facts";
  for (const [label, value] of [["PROTOCOL", result.protocol.toUpperCase()], ["HOSTNAME", result.hostname]]) {
    const fact = document.createElement("div");
    const factLabel = document.createElement("span");
    factLabel.textContent = label;
    const factValue = document.createElement("strong");
    factValue.textContent = value;
    fact.append(factLabel, factValue);
    facts.append(fact);
  }

  urlResult.append(
    header,
    summary,
    facts,
    createList("Warnings", result.warnings, "warning-list"),
    createList("Recommendations", result.recommendations, "recommendation-list"),
  );
  document.querySelector("#metric-url").textContent = result.risk_level.toUpperCase();
  document.querySelector("#metric-url-detail").textContent = result.hostname;
  document.querySelector("#metric-status").textContent = result.risk_level.toUpperCase();
  document.querySelector("#metric-status").style.color = `var(--${riskClass === "low" ? "green" : riskClass === "medium" ? "amber" : "coral"})`;
  document.querySelector("#metric-recommendations").textContent = String(result.recommendations.length).padStart(2, "0");
  document.querySelector("#metric-recommendations").nextElementSibling.textContent = "For this URL check";
}

function renderScanResult(result) {
  scanResult.className = "result-panel";
  scanResult.replaceChildren();
  const heading = document.createElement("div");
  heading.className = "result-header";
  const title = document.createElement("h3");
  title.textContent = result.host;
  const badge = document.createElement("span");
  badge.className = "risk-badge risk-low";
  badge.textContent = `${result.open_ports.length} OPEN`;
  heading.append(title, badge);

  const table = document.createElement("table");
  table.className = "scan-table";
  const head = document.createElement("thead");
  head.innerHTML = "<tr><th scope=\"col\">PORT</th><th scope=\"col\">STATUS</th></tr>";
  const body = document.createElement("tbody");
  for (const port of result.scanned_ports) {
    const row = document.createElement("tr");
    const portCell = document.createElement("td");
    portCell.textContent = String(port);
    const statusCell = document.createElement("td");
    const isOpen = result.open_ports.includes(port);
    statusCell.className = isOpen ? "port-open" : "port-closed";
    statusCell.textContent = result.errors.some((error) => error.port === port) ? "Error" : isOpen ? "Open" : "Closed";
    row.append(portCell, statusCell);
    body.append(row);
  }
  table.append(head, body);
  scanResult.append(heading, table);
  if (result.errors.length) {
    const errorNote = document.createElement("p");
    errorNote.className = "scan-caption";
    errorNote.textContent = `${result.errors.length} connection could not be completed.`;
    scanResult.append(errorNote);
  }
  document.querySelector("#metric-scan").textContent = "COMPLETE";
  document.querySelector("#metric-scan-detail").textContent = `${result.host} / ${result.scanned_ports.length} ports`;
}

function renderError(container, message) {
  container.className = "result-panel result-error";
  container.replaceChildren();
  const notice = document.createElement("p");
  notice.setAttribute("role", "alert");
  notice.textContent = message;
  container.append(notice);
}

function setScreenshotError(message) {
  renderError(screenshotResult, message);
}

function extractScreenshotUrls(text) {
  const matches = text.match(/(?<![@\w-])(?:https?:\/\/)?(?:www\.)?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?::\d{1,5})?(?:\/[^\s<>"']*)?/gi) || [];
  return [...new Set(matches.map((match) => match.replace(/[.,;:!?\])}]+$/g, "")))].slice(0, 5);
}

function findScreenshotWarnings(text, confidence) {
  const warnings = [];
  const lowerText = text.toLowerCase();
  const pressurePhrases = [
    "verify your account",
    "account suspended",
    "act now",
    "limited time",
    "urgent action",
    "gift card",
    "wire transfer",
  ];
  if (pressurePhrases.some((phrase) => lowerText.includes(phrase))) {
    warnings.push("The visible text includes urgency or payment wording sometimes used in scams.");
  }
  if (/\b(password|passcode|one[- ]time code|verification code)\b/i.test(text)) {
    warnings.push("The screenshot asks about credentials or a verification code; confirm the request independently.");
  }
  if (/http:\/\//i.test(text)) {
    warnings.push("The visible text includes an HTTP link without HTTPS transport encryption.");
  }
  if (confidence < 55) {
    warnings.push("OCR confidence is low, so some visible text may have been missed or misread.");
  }
  return warnings;
}

function createScreenshotSection(title, content) {
  const section = document.createElement("section");
  section.className = "screenshot-result-section";
  const heading = document.createElement("h4");
  heading.textContent = title;
  section.append(heading, content);
  return section;
}

function renderScreenshotResult(text, confidence, warnings, checkedUrls) {
  screenshotResult.className = "result-panel screenshot-result-panel";
  screenshotResult.replaceChildren();

  const title = document.createElement("h3");
  title.textContent = "Text-based screenshot review";
  const summary = document.createElement("p");
  summary.className = "result-summary";
  summary.textContent = text.trim()
    ? "OCR extracted visible text. These checks can flag clues, but cannot determine whether the screenshot or destination is safe."
    : "No readable text was detected. This screenshot check is inconclusive.";
  const risk = document.createElement("span");
  const riskLevel = !text.trim() ? "medium" : warnings.length >= 3 ? "high" : warnings.length ? "medium" : "low";
  risk.className = `risk-badge risk-${riskLevel}`;
  risk.textContent = !text.trim() ? "INCONCLUSIVE" : `${riskLevel.toUpperCase()} INDICATORS`;
  const header = document.createElement("div");
  header.className = "result-header";
  header.append(title, risk);

  const textOutput = document.createElement("pre");
  textOutput.className = "ocr-text-output";
  textOutput.textContent = text.trim() || "No readable text was found in this image.";
  const details = document.createElement("p");
  details.className = "scan-caption";
  details.textContent = `OCR confidence: ${Math.round(confidence)}%. Text recognition can be incomplete.`;

  const warningList = warnings.length ? warnings : ["No obvious text-based indicators were detected. This is not a guarantee of safety."];
  const warningContent = document.createElement("ul");
  warningContent.className = "result-list warning-list";
  for (const warning of warningList) {
    const item = document.createElement("li");
    item.textContent = warning;
    warningContent.append(item);
  }

  const recommendationContent = document.createElement("ul");
  recommendationContent.className = "result-list recommendation-list";
  for (const recommendation of [
    "Verify any displayed domain by typing a trusted address yourself rather than following a link in the image.",
    "Do not enter credentials or payment details based only on information shown in a screenshot.",
  ]) {
    const item = document.createElement("li");
    item.textContent = recommendation;
    recommendationContent.append(item);
  }

  screenshotResult.append(
    header,
    summary,
    details,
    createScreenshotSection("EXTRACTED TEXT", textOutput),
    createScreenshotSection("INDICATORS", warningContent),
    createScreenshotSection("RECOMMENDATIONS", recommendationContent),
  );

  if (checkedUrls.length) {
    const urlContent = document.createElement("div");
    for (const { url, result, error } of checkedUrls) {
      const item = document.createElement("div");
      item.className = "recognized-url";
      const label = document.createElement("strong");
      label.textContent = url;
      const status = document.createElement("span");
      status.textContent = result
        ? `${result.risk_level} risk: ${result.summary}`
        : `URL check unavailable: ${error}`;
      item.append(label, status);
      urlContent.append(item);
      if (result?.warnings.length) {
        const urlWarnings = document.createElement("ul");
        urlWarnings.className = "result-list warning-list";
        for (const warning of result.warnings) {
          const warningItem = document.createElement("li");
          warningItem.textContent = warning;
          urlWarnings.append(warningItem);
        }
        urlContent.append(urlWarnings);
      }
    }
    screenshotResult.append(createScreenshotSection("RECOGNIZED URLS", urlContent));
  }
}

screenshotInput.addEventListener("change", () => {
  const file = screenshotInput.files[0];
  const submitButton = document.querySelector("#screenshot-submit");
  const fileName = document.querySelector("#screenshot-file-name");
  if (screenshotObjectUrl) {
    URL.revokeObjectURL(screenshotObjectUrl);
    screenshotObjectUrl = null;
  }
  screenshotPreview.hidden = true;
  submitButton.disabled = true;
  screenshotResult.className = "result-panel empty-state";
  screenshotResult.innerHTML = '<div class="empty-glyph">▧</div><p>Screenshot findings will appear here.</p>';

  if (!file) {
    fileName.textContent = "No image selected";
    return;
  }
  if (!["image/png", "image/jpeg", "image/webp"].includes(file.type)) {
    fileName.textContent = "Unsupported image format";
    setScreenshotError("Choose a PNG, JPG, or WebP image.");
    return;
  }
  if (file.size > MAX_SCREENSHOT_BYTES) {
    fileName.textContent = "Image exceeds 5 MB";
    setScreenshotError("Choose an image smaller than 5 MB.");
    return;
  }

  fileName.textContent = file.name;
  screenshotObjectUrl = URL.createObjectURL(file);
  screenshotPreview.src = screenshotObjectUrl;
  screenshotPreview.hidden = false;
  submitButton.disabled = false;
});

screenshotForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = screenshotInput.files[0];
  if (!file) return;

  if (typeof Tesseract === "undefined") {
    setScreenshotError("OCR could not load. Check your internet connection and reload the page to download the OCR engine.");
    return;
  }

  const button = document.querySelector("#screenshot-submit");
  const progressPanel = document.querySelector("#ocr-progress");
  const progressBar = document.querySelector("#ocr-progress-bar");
  const progressStatus = document.querySelector("#ocr-status");
  const progressPercent = document.querySelector("#ocr-percent");
  let worker;
  button.disabled = true;
  button.querySelector("span").textContent = "Analyzing...";
  progressPanel.hidden = false;
  progressBar.value = 0;
  progressPercent.textContent = "0%";
  progressStatus.textContent = "Preparing screenshot...";
  screenshotResult.className = "result-panel empty-state";
  screenshotResult.replaceChildren();
  const loadingMessage = document.createElement("p");
  loadingMessage.textContent = "Reading visible text in your browser...";
  screenshotResult.append(loadingMessage);

  try {
    const image = await createImageBitmap(file);
    const pixelCount = image.width * image.height;
    image.close();
    if (pixelCount > MAX_SCREENSHOT_PIXELS) {
      throw new Error("This image is too large to process safely. Use an image with 25 megapixels or fewer.");
    }

    worker = await Tesseract.createWorker("eng", 1, {
      logger: (message) => {
        if (message.status) progressStatus.textContent = message.status;
        if (typeof message.progress === "number") {
          const percent = Math.round(message.progress * 100);
          progressBar.value = percent;
          progressPercent.textContent = `${percent}%`;
        }
      },
    });
    const { data } = await worker.recognize(file);
    const text = data.text || "";
    const warnings = findScreenshotWarnings(text, data.confidence || 0);
    const urlChecks = [];
    for (const url of extractScreenshotUrls(text)) {
      try {
        const result = await postJson("/security-check", { url: /^https?:\/\//i.test(url) ? url : `https://${url}` });
        urlChecks.push({ url, result });
      } catch (error) {
        urlChecks.push({ url, error: error.message });
      }
    }
    renderScreenshotResult(text, data.confidence || 0, warnings, urlChecks);
  } catch (error) {
    setScreenshotError(error.message || "The screenshot could not be analyzed. Try a clearer PNG, JPG, or WebP image.");
  } finally {
    if (worker) await worker.terminate();
    button.disabled = false;
    button.querySelector("span").textContent = "Analyze Screenshot";
    progressPanel.hidden = true;
  }
});

urlForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = document.querySelector("#url-submit");
  setLoading(button, true, "Check URL");
  try {
    const result = await postJson("/security-check", { url: document.querySelector("#url-input").value });
    renderUrlResult(result);
  } catch (error) {
    renderError(urlResult, error.message || "The URL could not be checked. Please try again.");
  } finally {
    setLoading(button, false, "Check URL");
  }
});

scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = document.querySelector("#scan-submit");
  setLoading(button, true, "Scan Ports");
  try {
    const result = await postJson("/scan", {
      host: document.querySelector("#host-input").value,
      ports: document.querySelector("#ports-input").value,
      confirm_authorized: document.querySelector("#authorization-input").checked,
    });
    renderScanResult(result);
  } catch (error) {
    renderError(scanResult, error.message || "The scan could not be completed. Please try again.");
  } finally {
    setLoading(button, false, "Scan Ports");
  }
});
