import { invoke } from "@tauri-apps/api/core";
import { DataSet, Network } from "vis-network/standalone";

// ==========================================
// Global Variables
// ==========================================
const container = document.getElementById("graph-container");
const statusLog = document.getElementById("status-log");
const detailsPanel = document.getElementById("details-panel");
const detailTitle = document.getElementById("detail-title");
const detailsBody = document.getElementById("details-body");
const btnClose = document.getElementById("btn-close-details");
const btnExpand = document.getElementById("btn-expand-details");

let network = null;
let nodes = null;
let edges = null;

const searchPanelGlobal = document.getElementById("search-panel");
const vendorsPanel = document.getElementById("vendors-panel");
const mainSearchPanel = document.querySelector(".search-panel");

const navDashboard = document.getElementById("nav-dashboard");
const navSearch = document.getElementById("nav-search");
const navVendors = document.getElementById("nav-vendors");
const btnCloseSearch = document.getElementById("btn-close-search");
const btnCloseVendors = document.getElementById("btn-close-vendors");

const globalSearchInput = document.getElementById("global-search-input");
const searchResults = document.getElementById("search-results");
const vendorFilterInput = document.getElementById("vendor-filter-input");
const vendorList = document.getElementById("vendor-list");

let lastChatMessage = "";
let currentChatCveId = "";
let currentSelectedModel = "nvidia/nemotron-3.5-lightning:free";

// Response versioning
let messageVersions = [];
let currentVersionIndex = -1;

// Global storage for the current conversation
let currentConversation = [];
let currentReportId = null;
// Primary vendor of the CVE currently open in chat; persisted with reports
let currentChatVendor = "";
// Guard against double-click race when opening a report
let isOpeningReport = false;
// Protection against race conditions
let isProcessing = false;

// Bulk selection state for reports panel
let selectedReportIds = new Set();
let isBulkSelectionMode = false;
// Client-side filter query for the reports panel
let reportsFilterQuery = "";

// Safe extraction of JSON from LLM responses
function extractJSON(text) {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch (e) {
    const match = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
    if (match) {
      try {
        return JSON.parse(match[1].trim());
      } catch (innerError) {
        console.error("Failed to parse extracted JSON:", innerError);
        return null;
      }
    }
    return null;
  }
}

// Processing state management (UI blocking)
function setProcessingState(state) {
  isProcessing = state;
  const sendBtn = document.getElementById("btn-send-chat");
  const chatInput = document.getElementById("chat-input");
  const regenBtns = document.querySelectorAll(".btn-regen");
  
  if (sendBtn) sendBtn.disabled = state;
  if (chatInput) chatInput.disabled = state;
  
  regenBtns.forEach(btn => {
    btn.disabled = state;
    btn.style.opacity = state ? "0.5" : "1";
    btn.style.cursor = state ? "not-allowed" : "pointer";
  });
}

// Render a transient loading placeholder WITHOUT markdown parsing.
// Keeps the spinner as a real DOM node so it can be replaced by ID later.
function addLoadingMessage(loadingId, label = "Agent is thinking...") {
  const chatHistory = document.getElementById("chat-history");
  if (!chatHistory) return;
  const msgDiv = document.createElement("div");
  msgDiv.className = "chat-message assistant";
  msgDiv.innerHTML = `<div id="${loadingId}" class="loading-spinner">${label}</div>`;
  chatHistory.appendChild(msgDiv);
  chatHistory.scrollTop = chatHistory.scrollHeight;
}

// ==========================================
// Graph Initialization
// ==========================================
btnClose.addEventListener("click", () => {
  detailsPanel.classList.add("hidden");
  if (network) network.unselectAll();
});

// Expand/collapse details panel with persisted state
if (btnExpand) {
  btnExpand.addEventListener("click", () => {
    const expanded = detailsPanel.classList.toggle("expanded");
    btnExpand.classList.toggle("active", expanded);
    btnExpand.title = expanded ? "Collapse panel" : "Expand panel";
    localStorage.setItem("details_expanded", expanded ? "1" : "0");
    localStorage.setItem("export_dir", exportDirInput.value.trim());
    // Notify vis-network so the canvas re-measures the resized container
    window.dispatchEvent(new Event("resize"));
  });
}

// Restore persisted expand state on startup
if (btnExpand && localStorage.getItem("details_expanded") === "1") {
  detailsPanel.classList.add("expanded");
  btnExpand.classList.add("active");
  btnExpand.title = "Collapse panel";
}

function initGraph(data) {
  // Destroy previous Network instance to prevent memory leaks and stale event listeners
  if (network) {
    network.destroy();
    network = null;
  }
  
  nodes = new DataSet(data.nodes);
  edges = new DataSet(data.edges);

  nodes.forEach((node) => {
    if (node.group === "cve" && node.details) {
      const cvss = node.details.cvss_score || 0;
      let color = "#eab308";
      if (cvss >= 9.0) color = "#ef4444";
      else if (cvss >= 7.0) color = "#f97316";
      else if (cvss < 4.0) color = "#22c55e";
      // KEV-CVEs get a thick pulsing red border regardless of CVSS
      const isKev = node.details.in_cisa_kev === true;
      node.color = {
        background: color,
        border: isKev ? "#ef4444" : color,
        highlight: { background: color, border: "#ffffff" }
      };
      node.borderWidth = isKev ? 3 : 1;
      node.borderWidthSelected = isKev ? 5 : 2;
    }
    if (node.group === "vendor") {
      node.color = { background: "#3b82f6", border: "#60a5fa", highlight: { background: "#60a5fa", border: "#ffffff" } };
    }
  });

  const isLightTheme = document.body.classList.contains("light-theme");
  const nodeFontColor = isLightTheme ? "#212529" : "#e8e8f0";
  const edgeColor = isLightTheme ? "#ced4da" : "#2a2a3a";

  const options = {
    nodes: { shape: "dot", size: 14, font: { color: nodeFontColor, size: 12, face: "Segoe UI" }, borderWidth: 1 },
    edges: { width: 1, color: { color: edgeColor, highlight: "#6a0dad" }, smooth: { type: "continuous" }, font: { size: 0 } },
    physics: {
      enabled: true,
      forceAtlas2Based: { gravitationalConstant: -60, centralGravity: 0.015, springLength: 150, springConstant: 0.06 },
      maxVelocity: 40, minVelocity: 0.5, solver: "forceAtlas2Based",
      stabilization: { iterations: 1500, fit: true, updateInterval: 25 },
    },
    interaction: { hover: true, tooltipDelay: 200, navigationButtons: true, keyboard: true },
  };

  network = new Network(container, { nodes, edges }, options);
  network.once("stabilized", () => { network.setOptions({ physics: { enabled: false } }); });

  network.on("click", (params) => {
    if (params.nodes.length > 0) {
      showNodeDetails(nodes.get(params.nodes[0]));
    } else {
      detailsPanel.classList.add("hidden");
    }
  });

  updateMetrics(data.nodes);
}

function updateMetrics(nodeList) {
  const cves = nodeList.filter((n) => n.group === "cve");
  const vendors = nodeList.filter((n) => n.group === "vendor");
  const critical = cves.filter((n) => n.details && n.details.cvss_score >= 9.0).length;
  const avgCvss = cves.length ? (cves.reduce((sum, n) => sum + (n.details?.cvss_score || 0), 0) / cves.length).toFixed(1) : "0.0";

  document.getElementById("metric-total").textContent = cves.length;
  document.getElementById("metric-critical").textContent = critical;
  document.getElementById("metric-vendors").textContent = vendors.length;
  document.getElementById("metric-avg-cvss").textContent = avgCvss;
  document.getElementById("badge-cves").textContent = cves.length;
  document.getElementById("badge-vendors").textContent = vendors.length;
}

// ==========================================
// Chat Logic
// ==========================================
async function loadModels() {
  try {
    const modelsStr = await invoke("get_available_models");
    const models = modelsStr.split(',');
    const selector = document.getElementById("model-selector");
    if (!selector) return;
    
    selector.innerHTML = "";
    models.forEach(model => {
      const option = document.createElement("option");
      option.value = model;
      option.textContent = model.split('/').pop().replace(':free', '').replace('-instruct', '');
      if (model === currentSelectedModel) option.selected = true;
      selector.appendChild(option);
    });
    
    selector.addEventListener("change", (e) => { currentSelectedModel = e.target.value; });
  } catch (error) {
    console.error("Failed to load models:", error);
  }
}

function copyToClipboard(text, btnElement) {
  navigator.clipboard.writeText(text).then(() => {
    const originalHTML = btnElement.innerHTML;
    btnElement.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`;
    setTimeout(() => { btnElement.innerHTML = originalHTML; }, 2000);
  });
}

function addChatMessage(role, text, isVersionUpdate = false) {
  const chatHistory = document.getElementById("chat-history");
  if (!chatHistory) return;

  const msgDiv = document.createElement("div");
  msgDiv.className = `chat-message ${role}`;
  let contentHTML = role === 'assistant' ? parseMarkdown(text) : `<p>${text}</p>`;

  if (role === 'assistant') {
    const tempDiv = document.createElement("div");
    tempDiv.innerHTML = contentHTML;
    const plainText = tempDiv.textContent || tempDiv.innerText || "";

    if (!isVersionUpdate) {
      messageVersions.push({ text, plainText });
      currentVersionIndex = messageVersions.length - 1;
    }

    const versionControls = messageVersions.length > 1 ? `
      <div class="version-controls">
        <button class="btn-version-nav" onclick="previousVersion()" title="Previous" ${currentVersionIndex === 0 ? 'disabled' : ''}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
        </button>
        <span class="version-indicator">${currentVersionIndex + 1}/${messageVersions.length}</span>
        <button class="btn-version-nav" onclick="nextVersion()" title="Next" ${currentVersionIndex === messageVersions.length - 1 ? 'disabled' : ''}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
        </button>
      </div>
    ` : '';

    contentHTML += `
      <div class="message-actions">
        ${versionControls}
        <button class="btn-copy" title="Copy">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        </button>
        <button class="btn-regen" title="Regenerate">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.3"/></svg>
        </button>
      </div>`;
  }

  msgDiv.innerHTML = contentHTML;
  chatHistory.appendChild(msgDiv);
  chatHistory.scrollTop = chatHistory.scrollHeight;

  if (role === 'assistant') {
    const finalTempDiv = document.createElement("div");
    finalTempDiv.innerHTML = parseMarkdown(text);
    const finalPlainText = finalTempDiv.textContent || finalTempDiv.innerText || "";

    const copyBtn = msgDiv.querySelector(".btn-copy");
    const regenBtn = msgDiv.querySelector(".btn-regen");

    if (copyBtn) {
      copyBtn.addEventListener("click", () => copyToClipboard(finalPlainText, copyBtn));
    }
    if (regenBtn) {
      regenBtn.addEventListener("click", () => regenerateMessage());
    }
  }
}

function regenerateMessage() {
  if (isProcessing || !lastChatMessage || !currentChatCveId) return;

  setProcessingState(true);

  const chatHistory = document.getElementById("chat-history");
  const assistantMsgs = chatHistory.querySelectorAll(".chat-message.assistant");
  
  if (assistantMsgs.length > 0) {
    assistantMsgs[assistantMsgs.length - 1].remove();
    if (currentConversation.length > 0 && currentConversation[currentConversation.length - 1].role === "assistant") {
      currentConversation.pop();
    }
  }

  const loadingId = "loading-" + Date.now();
  addLoadingMessage(loadingId, "Regenerating...");

  invoke("chat_with_agent", {
    cveId: currentChatCveId,
    messages: JSON.stringify(currentConversation),
    model: currentSelectedModel
  }).then(async (response) => {
    const loadingEl = document.getElementById(loadingId);
    if (loadingEl) {
      loadingEl.parentElement.remove();
    }
    currentConversation.push({ role: "assistant", content: response });
    addChatMessage("assistant", response, false);
    
    // Persist regenerated turn so reports stay in sync with UI
    if (currentConversation.length >= 2) {
      await autoSaveConversation();
    }
  }).catch(error => {
    const loadingEl = document.getElementById(loadingId);
    if (loadingEl) {
      loadingEl.parentElement.innerHTML = `<span class="error">Error: ${error}</span>`;
    }
  }).finally(() => {
    setProcessingState(false);
  });
}

window.previousVersion = function() {
  if (currentVersionIndex > 0) {
    currentVersionIndex--;
    updateVersionDisplay();
  }
};

window.nextVersion = function() {
  if (currentVersionIndex < messageVersions.length - 1) {
    currentVersionIndex++;
    updateVersionDisplay();
  }
};

function updateVersionDisplay() {
  const chatHistory = document.getElementById("chat-history");
  const assistantMsgs = chatHistory.querySelectorAll(".chat-message.assistant");
  const lastMsg = assistantMsgs[assistantMsgs.length - 1];

  if (lastMsg && messageVersions[currentVersionIndex]) {
    const version = messageVersions[currentVersionIndex];
    const contentHTML = parseMarkdown(version.text);

    const versionControls = `
      <div class="version-controls">
        <button class="btn-version-nav" onclick="previousVersion()" title="Previous" ${currentVersionIndex === 0 ? 'disabled' : ''}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
        </button>
        <span class="version-indicator">${currentVersionIndex + 1}/${messageVersions.length}</span>
        <button class="btn-version-nav" onclick="nextVersion()" title="Next" ${currentVersionIndex === messageVersions.length - 1 ? 'disabled' : ''}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
        </button>
      </div>
    `;

    lastMsg.innerHTML = contentHTML + `
      <div class="message-actions">
        ${versionControls}
        <button class="btn-copy" title="Copy">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        </button>
        <button class="btn-regen" title="Regenerate">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.3"/></svg>
        </button>
      </div>`;

    const copyBtn = lastMsg.querySelector(".btn-copy");
    const regenBtn = lastMsg.querySelector(".btn-regen");
    
    const tempDiv = document.createElement("div");
    tempDiv.innerHTML = contentHTML;
    const plainText = tempDiv.textContent || tempDiv.innerText || "";

    if (copyBtn) {
      copyBtn.addEventListener("click", () => copyToClipboard(plainText, copyBtn));
    }
    if (regenBtn) {
      regenBtn.addEventListener("click", () => regenerateMessage());
    }
  }
}

async function sendChatMessage(isRegenerate = false) {
  if (isProcessing) return;

  const chatInput = document.getElementById("chat-input");
  const message = isRegenerate ? lastChatMessage : chatInput.value.trim();
  if (!message || !currentChatCveId) return;

  setProcessingState(true);

  if (!isRegenerate) {
    addChatMessage("user", message);
    chatInput.value = "";
    lastChatMessage = message;
    
    currentConversation.push({ role: "user", content: message });
    if (currentConversation.length > 10) {
      currentConversation = currentConversation.slice(-10);
    }
  }

  const loadingId = "loading-" + Date.now();
  addLoadingMessage(loadingId);

  try {
    const response = await invoke("chat_with_agent", { 
      cveId: currentChatCveId, 
      messages: JSON.stringify(currentConversation),
      model: currentSelectedModel 
    });
    
    const loadingEl = document.getElementById(loadingId);
    if (loadingEl) {
      loadingEl.parentElement.remove();
    }
    
    currentConversation.push({ role: "assistant", content: response });
    if (currentConversation.length > 10) {
      currentConversation = currentConversation.slice(-10);
    }
    
    addChatMessage("assistant", response, false);
    
    if (currentConversation.length >= 2) {
      await autoSaveConversation();
    }
    
  } catch (error) {
    const loadingEl = document.getElementById(loadingId);
    if (loadingEl) {
      loadingEl.parentElement.innerHTML = `<span class="error">Error: ${error}</span>`;
    }
  } finally {
    setProcessingState(false);
  }
}

async function autoSaveConversation() {
  if (!currentChatCveId || currentConversation.length === 0) return;
  
  const title = `Chat ${new Date().toLocaleString()} - ${currentChatCveId}`;
  const messagesJson = JSON.stringify(currentConversation);
  
  try {
    currentReportId = await invoke("save_chat_report", {
      cveId: currentChatCveId,
      title: title,
      messages: messagesJson,
      model: currentSelectedModel,
      vendor: currentChatVendor 
    });
  } catch (error) {
    console.error("Failed to save conversation:", error);
  }
}

// Export current conversation to Markdown via Rust fs
// (WebView2 silently ignores blob: downloads, so we write via Tauri command)
async function exportCurrentConversation() {
  if (!currentChatCveId || currentConversation.length === 0) {
    statusLog.textContent = "No conversation to export";
    return;
  }

  const timestamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
  const filename = `${currentChatCveId}_${timestamp}.md`;

  let md = `# Panopticon Report: ${currentChatCveId}\n\n`;
  md += `**Generated:** ${new Date().toLocaleString()}\n`;
  md += `**Model:** ${currentSelectedModel}\n`;
  md += `**Messages:** ${currentConversation.length}\n\n`;
  md += `---\n\n`;

  currentConversation.forEach((msg, idx) => {
    const role = msg.role === "user" ? "👤 User" : "🤖 Assistant";
    md += `## ${role}\n\n`;
    md += msg.content + "\n\n";
    if (idx < currentConversation.length - 1) md += `---\n\n`;
  });

  md += `\n\n---\n*Generated by Panopticon CVE Intelligence Map*\n`;

  try {
    const exportDir = localStorage.getItem("export_dir") || "";
    const savedPath = await invoke("export_markdown", { filename, content: md, dir: exportDir });
    statusLog.textContent = `Report saved: ${savedPath}`;
  } catch (err) {
    console.error("Export failed:", err);
    statusLog.textContent = `Export failed: ${err}`;
  }
}

// Open a saved report: rebuild the graph around its CVE and restore the chat.
async function openReport(reportId) {
  if (isOpeningReport) return;
  isOpeningReport = true;
  try {
    const report = JSON.parse(await invoke("load_chat_report", { reportId }));
    currentReportId = reportId;
    hideAllPanels();

    statusLog.textContent = `Loading saved conversation for ${report.cve_id}...`;

    let loaded = await loadSpecificCVE(report.cve_id, { silent: true, showMainPanel: false });
    if (!loaded && report.vendor && report.vendor.trim() !== "") {
      loaded = await loadSpecificCVE(report.cve_id, { 
        vendor: report.vendor, 
        silent: true, 
        showMainPanel: false 
      });
    }

    if (loaded) {
      restoreConversation(report);
      statusLog.textContent = "Ready";
    } else {
      statusLog.textContent = `CVE ${report.cve_id} not found. Try loading its vendor manually.`;
    }
  } catch (error) {
    console.error("Failed to open report:", error);
    statusLog.textContent = `Error: ${error}`;
  } finally {
    isOpeningReport = false;
  }
}

// Fill the details-panel chat with messages from a saved report.
function restoreConversation(report) {
  const chatContainer = document.getElementById("mitigation-chat-container");
  const chatBtn = document.getElementById("btn-start-mitigation-chat");
  const chatHistory = document.getElementById("chat-history");
  if (!chatContainer || !chatHistory) return;

  if (chatBtn) chatBtn.classList.add("hidden");
  const modelSelect = document.querySelector(".chat-controls select");
  if (modelSelect) modelSelect.classList.add("hidden");
  chatContainer.classList.remove("hidden");

  chatHistory.innerHTML = "";
  currentConversation = [];
  messageVersions = [];
  currentVersionIndex = -1;

  report.messages.forEach(msg => {
    addChatMessage(msg.role, msg.content, true);
    currentConversation.push(msg);
  });

  currentChatCveId = report.cve_id;
  currentChatVendor = report.vendor || "";
  const lastUser = [...report.messages].reverse().find(m => m.role === "user");
  lastChatMessage = lastUser ? lastUser.content : "";

  if (report.messages.length === 0) {
    addChatMessage("assistant", "Saved conversation data is empty or was corrupted.", true);
  }
}

function showNodeDetails(node) {
  detailsPanel.classList.remove("hidden");
  detailTitle.textContent = node.label;

  if (node.group === "vendor") {
    const relatedCves = nodes.get().filter((n) => n.group === "cve" && edges.get().some((e) => e.from === node.id && e.to === n.id || e.to === node.id && e.from === n.id));
    const criticalCount = relatedCves.filter((n) => n.details?.cvss_score >= 9.0).length;
    const avgCvss = relatedCves.length ? (relatedCves.reduce((sum, n) => sum + (n.details?.cvss_score || 0), 0) / relatedCves.length).toFixed(1) : "N/A";

    detailsBody.innerHTML = `
      <div class="detail-row"><span class="label">Type</span><span class="value">Vendor</span></div>
      <div class="detail-row"><span class="label">Related CVEs</span><span class="value">${relatedCves.length}</span></div>
      <div class="detail-row"><span class="label">Critical</span><span class="value severity-critical">${criticalCount}</span></div>
      <div class="detail-row"><span class="label">Avg CVSS</span><span class="value">${avgCvss}</span></div>
      <div class="detail-section">
        <h4>Related CVEs</h4>
        <ul>
          ${relatedCves.slice(0, 10).map((n) => `<li><a href="#" onclick="focusNode('${n.id}'); return false;">${n.label}</a> <span class="severity-${n.details?.severity?.toLowerCase() || 'unknown'}">${n.details?.severity || 'N/A'}</span></li>`).join("")}
          ${relatedCves.length > 10 ? `<li>... and ${relatedCves.length - 10} more</li>` : ""}
        </ul>
      </div>`;
  } else if (node.details) {
    const d = node.details;
    const sevClass = `severity-${(d.severity || "unknown").toLowerCase()}`;
    
    detailsBody.innerHTML = `
      <div class="details-header-actions">
        <button id="btn-export-report" class="btn-icon" title="Export to Markdown">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
            <polyline points="7 10 12 15 17 10"></polyline>
            <line x1="12" y1="15" x2="12" y2="3"></line>
          </svg>
        </button>
      </div>
      
      <div class="chat-controls">
        <select id="model-selector" class="model-selector" title="Select AI Model">
          <option value="loading">Loading...</option>
        </select>
        <button id="btn-start-mitigation-chat" class="btn-mitigation" style="flex:1; margin-bottom:0;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
          Start Chat
        </button>
      </div>
      
      <div id="mitigation-chat-container" class="mitigation-chat-container hidden">
        <div id="chat-history" class="chat-history"></div>
        <div class="chat-input-area">
          <input type="text" id="chat-input" placeholder="Ask a follow-up question..." />
          <button id="btn-send-chat" class="btn-send">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
          </button>
        </div>
      </div>

      <div class="detail-row"><span class="label">CVSS</span><span class="value">${d.cvss_score ?? "N/A"}</span></div>
      <div class="detail-row"><span class="label">Severity</span><span class="value ${sevClass}">${d.severity || "UNKNOWN"}</span></div>
      ${d.in_cisa_kev ? `
      <div class="detail-row kev-alert">
        <span class="label">🔥 CISA KEV</span>
        <span class="value">ACTIVELY EXPLOITED</span>
      </div>
      <div class="detail-row"><span class="label">KEV Due</span><span class="value">${d.kev_details?.due_date || "N/A"}</span></div>
      ` : ''}
      <div class="detail-row"><span class="label">CWE</span><span class="value">${d.cwe_ids?.join(", ") || "N/A"}</span></div>
      <div class="detail-row"><span class="label">Published</span><span class="value">${d.published_date ? d.published_date.split("T")[0] : "N/A"}</span></div>
      <div class="detail-section"><h4>Description</h4><p>${d.description || "No description available."}</p></div>
      <div class="detail-section"><h4>Affected Products</h4><ul>${(d.affected_products || []).map((p) => `<li>${p.vendor} ${p.product} ${p.version || ""}</li>`).join("") || "<li>None</li>"}</ul></div>
      <div class="detail-section"><h4>References</h4><ul>${(() => {
        const refs = d.references || [];
        const seen = new Set();
        const unique = refs.filter(r => {
          try {
            const domain = new URL(r.url).hostname;
            if (seen.has(domain)) return false;
            seen.add(domain);
            return true;
          } catch { return true; }
        });
        return unique.length ? unique.map(r => `<li><a href="${r.url}" target="_blank">${r.source || new URL(r.url).hostname}</a></li>`).join("") : "<li>None</li>";
      })()}</ul></div>`;

    const chatBtn = document.getElementById("btn-start-mitigation-chat");
    const chatContainer = document.getElementById("mitigation-chat-container");
    const chatInput = document.getElementById("chat-input");
    const sendBtn = document.getElementById("btn-send-chat");
    const modelSelector = document.getElementById("model-selector");
    const exportBtn = document.getElementById("btn-export-report");
    
    currentChatCveId = d.cve_id;
    // Remember the primary vendor so saved reports can rebuild a vendor-scoped graph
    currentChatVendor = (d.affected_products && d.affected_products[0] && d.affected_products[0].vendor) || "";

    loadModels().then(() => {
      if (modelSelector) {
        Array.from(modelSelector.options).forEach(opt => {
          if (opt.value === currentSelectedModel) opt.selected = true;
        });
      }
    });

    // Re-attach export listener after innerHTML assignment (innerHTML destroys previous listeners)
    if (exportBtn) {
      exportBtn.addEventListener("click", exportCurrentConversation);
    }

    chatBtn.addEventListener("click", async () => {
      chatBtn.classList.add("hidden");
      document.querySelector(".chat-controls select").classList.add("hidden");
      chatContainer.classList.remove("hidden");
      
      currentConversation = [];
      messageVersions = [];
      currentVersionIndex = -1;
      currentReportId = null;
      
      addChatMessage("assistant", `🔍 Analyzing ${currentChatCveId}...`);
      
      try {
        const initialMitigation = await invoke("generate_mitigation", { cveId: currentChatCveId, model: currentSelectedModel });
        document.getElementById("chat-history").innerHTML = "";
        addChatMessage("assistant", initialMitigation, false);
        
        currentConversation.push({ role: "assistant", content: initialMitigation });
      } catch (error) {
        document.getElementById("chat-history").innerHTML = "";
        addChatMessage("assistant", `❌ Error: ${error}`);
      }
    });

    sendBtn.addEventListener("click", () => sendChatMessage(false));
    chatInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter") sendChatMessage(false);
    });
  } else {
    detailsBody.innerHTML = `<div class="detail-row"><span class="label">Type</span><span class="value">${node.group}</span></div>`;
  }
}

window.focusNode = function(nodeId) {
  network.focus(nodeId, { animation: { duration: 500, easingFunction: "easeInOutQuad" }, scale: 1.5 });
  const node = nodes.get(nodeId);
  if (node) showNodeDetails(node);
};

document.getElementById("btn-load").addEventListener("click", async () => {
  const vendorInput = document.getElementById("vendor-search").value.trim();
  const yearInput = document.getElementById("year-filter").value;
  const vendor = vendorInput || null;
  const minYear = yearInput ? parseInt(yearInput) : null;

  statusLog.textContent = "Fetching data...";
  document.getElementById("status-text").textContent = "Loading...";
  detailsPanel.classList.add("hidden");

  try {
    const rawData = await invoke("get_graph_data", { vendor, minYear });
    const graphData = JSON.parse(rawData);
    initGraph(graphData);
    statusLog.textContent = `Loaded ${graphData.nodes.length} nodes.`;
    document.getElementById("status-text").textContent = "Ready";
  } catch (error) {
    statusLog.textContent = `Error: ${error}`;
    document.getElementById("status-text").textContent = "Error";
    console.error(error);
  }
});

function parseMarkdown(text) {
  if (!text) return "";
  
  let safeText = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  
  return safeText
    .replace(/^### (.*$)/gm, '<h3>$1</h3>')
    .replace(/^## (.*$)/gm, '<h2>$1</h2>')
    .replace(/^# (.*$)/gm, '<h1>$1</h1>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/^- (.*$)/gm, '<li>$1</li>')
    .replace(/^\d+\. (.*$)/gm, '<li>$1</li>')
    .replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
    .replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/\n/g, '<br>');
}

// ==========================================
// Light/Dark Theme Toggle
// ==========================================
const themeToggle = document.getElementById("theme-toggle");
const themeIconMoon = document.getElementById("theme-icon-moon");
const themeIconSun = document.getElementById("theme-icon-sun");

const savedTheme = localStorage.getItem("theme") || "dark";
if (savedTheme === "light") {
  document.body.classList.add("light-theme");
  themeIconMoon.style.display = "none";
  themeIconSun.style.display = "block";
}

themeToggle.addEventListener("click", () => {
  const isLight = document.body.classList.toggle("light-theme");
  localStorage.setItem("theme", isLight ? "light" : "dark");
  
  themeIconMoon.style.display = isLight ? "none" : "block";
  themeIconSun.style.display = isLight ? "block" : "none";
  
  if (network) {
    const nodeFontColor = isLight ? "#212529" : "#e8e8f0";
    const edgeColor = isLight ? "#ced4da" : "#2a2a3a";
    network.setOptions({ nodes: { font: { color: nodeFontColor } }, edges: { color: { color: edgeColor } } });
  }
});

// ==========================================
// Settings Popover
// ==========================================
const navUserBtn = document.getElementById("nav-user-btn");
const settingsPopover = document.getElementById("settings-popover");
const btnClosePopover = document.getElementById("btn-close-popover");
const btnSaveSettings = document.getElementById("btn-save-settings");
const nvdApiKeyInput = document.getElementById("nvd-api-key");
const openrouterApiKeyInput = document.getElementById("openrouter-api-key");
const exportDirInput = document.getElementById("export-dir");

nvdApiKeyInput.value = localStorage.getItem("nvd_api_key") || "";
openrouterApiKeyInput.value = localStorage.getItem("openrouter_api_key") || "";
exportDirInput.value = localStorage.getItem("export_dir") || "";

navUserBtn.addEventListener("click", (e) => { e.stopPropagation(); settingsPopover.classList.toggle("hidden"); });
btnClosePopover.addEventListener("click", (e) => { e.stopPropagation(); settingsPopover.classList.add("hidden"); });
document.addEventListener("click", (e) => {
  if (!settingsPopover.contains(e.target) && !navUserBtn.contains(e.target)) settingsPopover.classList.add("hidden");
});
btnSaveSettings.addEventListener("click", (e) => {
  e.stopPropagation();
  localStorage.setItem("nvd_api_key", nvdApiKeyInput.value.trim());
  localStorage.setItem("openrouter_api_key", openrouterApiKeyInput.value.trim());
  const statusText = document.getElementById("status-text");
  statusText.textContent = "Settings saved";
  setTimeout(() => { statusText.textContent = "Ready"; }, 2000);
  settingsPopover.classList.add("hidden");
});

// ==========================================
// Panel Management
// ==========================================
const reportsPanel = document.getElementById("reports-panel");
const btnCloseReports = document.getElementById("btn-close-reports");
const navReports = document.getElementById("nav-reports");

let currentActivePanel = 'main';

function hideAllPanels() {
  if (searchPanelGlobal) searchPanelGlobal.classList.add("hidden");
  if (vendorsPanel) vendorsPanel.classList.add("hidden");
  if (mainSearchPanel) mainSearchPanel.classList.add("hidden");
  if (reportsPanel) reportsPanel.classList.add("hidden");
  currentActivePanel = 'none';
}

function showPanel(panelToShow) {
  hideAllPanels();
  if (panelToShow === "search") {
    searchPanelGlobal.classList.remove("hidden");
    globalSearchInput.value = "";
    searchResults.innerHTML = '<div class="loading-search">Start typing to search...</div>';
    globalSearchInput.focus();
    currentActivePanel = 'search';
  } else if (panelToShow === "vendors") {
    vendorsPanel.classList.remove("hidden");
    vendorFilterInput.value = "";
    loadVendors("");
    currentActivePanel = 'vendors';
  } else if (panelToShow === "reports") {
    if (reportsPanel) {
      reportsPanel.classList.remove("hidden");
      loadReportsList().catch(err => console.error("Failed to load reports:", err));
    }
    currentActivePanel = 'reports';
  } else if (panelToShow === "main") {
    mainSearchPanel.classList.remove("hidden");
    currentActivePanel = 'main';
  }
}

function setupNavToggle(navElement, panelName) {
  if (!navElement) return;
  let clickTimer = null;
  
  navElement.addEventListener("click", (e) => {
    e.preventDefault();
    if (clickTimer) {
      clearTimeout(clickTimer);
      clickTimer = null;
      hideAllPanels();
    } else {
      clickTimer = setTimeout(() => {
        clickTimer = null;
        if (currentActivePanel === panelName) { 
          hideAllPanels(); 
        } else { 
          showPanel(panelName); 
        }
      }, 250);
    }
  });
}

if (navDashboard) {
  let dashClickTimer = null;
  navDashboard.addEventListener("click", (e) => {
    e.preventDefault();
    if (dashClickTimer) {
      clearTimeout(dashClickTimer); dashClickTimer = null; hideAllPanels();
    } else {
      dashClickTimer = setTimeout(() => {
        dashClickTimer = null; showPanel("main");
      }, 250);
    }
  });
}

setupNavToggle(navSearch, "search");
setupNavToggle(navVendors, "vendors");
setupNavToggle(navReports, "reports");

if (btnCloseSearch) btnCloseSearch.addEventListener("click", () => hideAllPanels());
if (btnCloseVendors) btnCloseVendors.addEventListener("click", () => hideAllPanels());
if (btnCloseReports) btnCloseReports.addEventListener("click", () => hideAllPanels());

// ==========================================
// Global Search & Vendors
// ==========================================
let searchTimeout = null;
globalSearchInput.addEventListener("input", (e) => {
  clearTimeout(searchTimeout);
  const query = e.target.value.trim();
  if (query.length < 2) {
    searchResults.innerHTML = '<div class="loading-search">Start typing to search...</div>';
    return;
  }
  searchTimeout = setTimeout(async () => { await performGlobalSearch(query); }, 300);
});

async function performGlobalSearch(query) {
  searchResults.innerHTML = '<div class="loading-search">Searching...</div>';
  try {
    const rawData = await invoke("global_search", { query });
    const results = JSON.parse(rawData);
    if (results.length === 0) {
      searchResults.innerHTML = '<div class="no-results">No results found</div>';
      return;
    }
    searchResults.innerHTML = results.map(r => `
      <div class="search-result-item" data-type="${r.type}" data-id="${r.id}">
        <div>
          <div class="result-type">${r.type}</div>
          <div class="result-title">${r.title}</div>
          <div class="result-subtitle">${r.subtitle}</div>
        </div>
      </div>`).join("");
    
    document.querySelectorAll(".search-result-item").forEach(item => {
      item.addEventListener("click", async () => {
        const type = item.dataset.type;
        const id = item.dataset.id;
        if (type === "CVE") { await loadSpecificCVE(id); } 
        else if (type === "Vendor") {
          document.getElementById("vendor-search").value = id;
          showPanel("main");
          document.getElementById("btn-load").click();
        }
      });
    });
  } catch (error) {
    searchResults.innerHTML = `<div class="no-results">Error: ${error}</div>`;
    console.error(error);
  }
}

async function loadSpecificCVE(cveId, options = {}) {
  const { vendor = null, minYear = null, showMainPanel = true, silent = false } = options;
  try {
    if (!silent) {
      statusLog.textContent = `Loading ${cveId}...`;
      document.getElementById("status-text").textContent = "Loading...";
    }
    detailsPanel.classList.add("hidden");

    const rawData = await invoke("get_graph_data", { vendor, minYear });
    const graphData = JSON.parse(rawData);
    const cveNode = graphData.nodes.find(n => n.label === cveId);

    if (!cveNode) {
      if (!silent) {
        statusLog.textContent = `CVE ${cveId} not found in current dataset`;
        document.getElementById("status-text").textContent = "Error";
      }
      return false;
    }

    initGraph(graphData);
    // Wait for physics stabilization (capped) to avoid focusing a moving target
    await Promise.race([
      new Promise(resolve => network.once("stabilized", resolve)),
      new Promise(resolve => setTimeout(resolve, 1500))
    ]);
    network.focus(cveNode.id, { animation: { duration: 1000, easingFunction: "easeInOutQuad" }, scale: 2.0 });
    network.selectNodes([cveNode.id]);
    showNodeDetails(cveNode);
    statusLog.textContent = `Loaded ${cveId}`;
    document.getElementById("status-text").textContent = "Ready";
    if (showMainPanel) showPanel("main");
    return true;
  } catch (error) {
    if (!silent) {
      statusLog.textContent = `Error: ${error}`;
      document.getElementById("status-text").textContent = "Error";
    }
    console.error(error);
    return false;
  }
}

let vendorFilterTimeout = null;
vendorFilterInput.addEventListener("input", (e) => {
  clearTimeout(vendorFilterTimeout);
  vendorFilterTimeout = setTimeout(async () => { await loadVendors(e.target.value.trim()); }, 300);
});

async function loadVendors(query) {
  vendorList.innerHTML = '<div class="loading-vendors">Loading vendors...</div>';
  try {
    const rawData = await invoke("get_vendors", { query: query || null });
    const vendors = JSON.parse(rawData);
    if (vendors.length === 0) {
      vendorList.innerHTML = '<div class="no-vendors">No vendors found</div>';
      return;
    }
    vendorList.innerHTML = vendors.map(v => `
      <div class="vendor-item" data-vendor="${v.vendor}">
        <span class="vendor-name">${v.vendor}</span>
        <span class="vendor-count">${v.cve_count} CVEs</span>
      </div>`).join("");
    
    document.querySelectorAll(".vendor-item").forEach(item => {
      item.addEventListener("click", () => {
        document.getElementById("vendor-search").value = item.dataset.vendor;
        showPanel("main");
        document.getElementById("btn-load").click();
      });
    });
  } catch (error) {
    vendorList.innerHTML = `<div class="no-vendors">Error: ${error}</div>`;
    console.error(error);
  }
}

// ==========================================
// Reports Panel with Bulk Selection, Pins, and Tags
// ==========================================

// Toggle bulk selection mode for reports
function toggleBulkSelectionMode() {
  isBulkSelectionMode = !isBulkSelectionMode;
  selectedReportIds.clear();
  
  const toggleBtn = document.getElementById("btn-bulk-toggle");
  const deleteBulkBtn = document.getElementById("btn-bulk-delete");
  const selectAllBtn = document.getElementById("btn-select-all");
  
  if (isBulkSelectionMode) {
    if (toggleBtn) toggleBtn.classList.add("active");
    if (deleteBulkBtn) deleteBulkBtn.classList.remove("hidden");
    if (selectAllBtn) selectAllBtn.classList.remove("hidden");
  } else {
    if (toggleBtn) toggleBtn.classList.remove("active");
    if (deleteBulkBtn) deleteBulkBtn.classList.add("hidden");
    if (selectAllBtn) selectAllBtn.classList.add("hidden");
  }
  
  loadReportsList().catch(err => console.error(err));
}

// Select/deselect all visible reports
function toggleSelectAllReports() {
  const checkboxes = document.querySelectorAll(".report-checkbox");
  const allChecked = Array.from(checkboxes).every(cb => cb.checked);
  
  checkboxes.forEach(cb => {
    cb.checked = !allChecked;
    const id = parseInt(cb.dataset.id);
    if (!allChecked) selectedReportIds.add(id);
    else selectedReportIds.delete(id);
  });
  updateBulkDeleteCounter();
}

// Handle individual checkbox toggle
function toggleReportSelection(reportId, isChecked) {
  if (isChecked) selectedReportIds.add(reportId);
  else selectedReportIds.delete(reportId);
  updateBulkDeleteCounter();
}

function updateBulkDeleteCounter() {
  const btn = document.getElementById("btn-bulk-delete");
  if (!btn) return;
  const count = selectedReportIds.size;
  btn.textContent = count > 0 ? `Delete ${count}` : "Delete";
  btn.disabled = count === 0;
}

// Execute bulk delete
async function executeBulkDelete() {
  if (selectedReportIds.size === 0) return;
  
  const ids = Array.from(selectedReportIds);
  if (!confirm(`Delete ${ids.length} conversation(s) permanently?`)) return;
  
  try {
    await invoke("delete_chat_reports", { reportIds: JSON.stringify(ids) });
    
    ids.forEach(id => {
      const el = document.querySelector(`.report-item[data-id="${id}"]`);
      if (el) el.remove();
      if (currentReportId === id) currentReportId = null;
    });
    
    selectedReportIds.clear();
    updateBulkDeleteCounter();
    
    if (document.querySelectorAll(".report-item").length === 0) {
      toggleBulkSelectionMode();
    }
  } catch (err) {
    console.error("Bulk delete failed:", err);
  }
}

// Toggle pin for a single report
async function toggleReportPin(reportId) {
  try {
    const result = JSON.parse(await invoke("toggle_report_pin", { reportId }));
    if (result.pinned !== null) {
      loadReportsList().catch(err => console.error(err));
    }
  } catch (err) {
    console.error("Failed to toggle pin:", err);
  }
}

// Set tags for a report
async function setReportTags(reportId) {
  const currentTags = prompt("Enter tags (comma-separated, max 8):", "");
  if (currentTags === null) return;
  
  const tagsArray = currentTags.split(",").map(t => t.trim()).filter(t => t.length > 0);
  
  try {
    await invoke("set_report_tags", { 
      reportId, 
      tags: JSON.stringify(tagsArray) 
    });
    loadReportsList().catch(err => console.error(err));
  } catch (err) {
    console.error("Failed to set tags:", err);
  }
}

// Load and render the list of saved conversations
async function loadReportsList() {
  const reportsListEl = document.getElementById("reports-list");
  if (!reportsListEl) return;
  
  reportsListEl.innerHTML = '<div class="loading-reports">Loading reports...</div>';
  
  try {
    const rawData = await invoke("get_chat_reports", { cveId: "" });
    const reports = JSON.parse(rawData);
    // Apply client-side filter (CVE id, title, tags)
    const q = reportsFilterQuery.toLowerCase();
    const visibleReports = reportsFilterQuery
      ? reports.filter(r =>
          r.cve_id.toLowerCase().includes(q) ||
          r.title.toLowerCase().includes(q) ||
          (r.tags || []).some(t => t.toLowerCase().includes(q)))
      : reports;
    
    if (visibleReports.length === 0) {
      reportsListEl.innerHTML = reports.length === 0
        ? '<div class="no-reports">No saved conversations yet</div>'
        : '<div class="no-reports">No reports match your filter</div>';
      return;
    }
    
    // Add bulk controls header (only once)
    const existingHeader = reportsListEl.parentElement.querySelector(".panel-header-actions");
    if (!existingHeader) {
      const panelHeader = reportsListEl.parentElement.querySelector(".panel-header");
      if (panelHeader) {
        const headerHtml = `
          <div class="panel-header-actions">
            <button id="btn-bulk-toggle" class="btn-icon ${isBulkSelectionMode ? 'active' : ''}" title="Bulk selection">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="9 11 12 14 22 4"></polyline>
                <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path>
              </svg>
            </button>
            <button id="btn-select-all" class="btn-icon ${isBulkSelectionMode ? '' : 'hidden'}" title="Select all">All</button>
            <button id="btn-bulk-delete" class="btn-icon btn-danger ${isBulkSelectionMode ? '' : 'hidden'}" title="Delete selected" disabled>Delete</button>
          </div>`;
        panelHeader.insertAdjacentHTML("beforeend", headerHtml);
      }
    }
    
    reportsListEl.innerHTML = visibleReports.map(r => `
      <div class="report-item ${r.pinned ? 'pinned' : ''}" data-id="${r.id}">
        ${isBulkSelectionMode ? `
          <input type="checkbox" class="report-checkbox" data-id="${r.id}" 
                 ${selectedReportIds.has(r.id) ? 'checked' : ''} />
        ` : ''}
        <div class="report-content">
          <div class="report-header-row">
            <div class="report-cve">${r.pinned ? '📌 ' : ''}${r.cve_id}</div>
            <div class="report-actions">
              <button class="btn-pin-report" data-id="${r.id}" title="${r.pinned ? 'Unpin' : 'Pin'}">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="${r.pinned ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2">
                  <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/>
                </svg>
              </button>
              <button class="btn-tag-report" data-id="${r.id}" title="Tags">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"></path>
                  <line x1="7" y1="7" x2="7.01" y2="7"></line>
                </svg>
              </button>
              <button class="btn-delete-report" data-id="${r.id}" title="Delete">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <polyline points="3 6 5 6 21 6"></polyline>
                  <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                </svg>
              </button>
            </div>
          </div>
          <div class="report-title">${r.title}</div>
          ${r.tags && r.tags.length > 0 ? `
            <div class="report-tags">
              ${r.tags.map(tag => `<span class="tag-chip">${tag}</span>`).join("")}
            </div>
          ` : ''}
          <div class="report-date">${new Date(r.created_at).toLocaleString()}</div>
          <div class="report-model">${r.model.split('/').pop().replace(':free', '')}</div>
        </div>
      </div>
    `).join("");

    // Wire up event listeners
    document.getElementById("btn-bulk-toggle")?.addEventListener("click", toggleBulkSelectionMode);
    document.getElementById("btn-select-all")?.addEventListener("click", toggleSelectAllReports);
    document.getElementById("btn-bulk-delete")?.addEventListener("click", executeBulkDelete);

    // Checkbox handlers (bulk mode)
    document.querySelectorAll(".report-checkbox").forEach(cb => {
      cb.addEventListener("change", (e) => {
        toggleReportSelection(parseInt(e.target.dataset.id), e.target.checked);
      });
    });

    // Click to open report (ignore if clicking buttons or checkboxes)
    document.querySelectorAll(".report-item").forEach(item => {
      item.addEventListener("click", async (e) => {
        if (e.target.closest(".report-checkbox, .btn-delete-report, .btn-pin-report, .btn-tag-report")) return;
        const reportId = parseInt(item.dataset.id);
        hideAllPanels();
        await openReport(reportId);
      });
    });

    // Pin button handlers
    document.querySelectorAll(".btn-pin-report").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const reportId = parseInt(btn.dataset.id);
        await toggleReportPin(reportId);
      });
    });

    // Tag button handlers
    document.querySelectorAll(".btn-tag-report").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const reportId = parseInt(btn.dataset.id);
        await setReportTags(reportId);
      });
    });

    // Delete button handlers (single delete)
    document.querySelectorAll(".btn-delete-report").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const reportId = parseInt(btn.dataset.id);
        if (confirm("Delete this conversation permanently?")) {
          try {
            await invoke("delete_chat_report", { reportId });
            btn.closest(".report-item").remove();
            if (currentReportId === reportId) {
              currentReportId = null;
            }
          } catch (err) {
            console.error("Failed to delete report:", err);
          }
        }
      });
    });
    
    updateBulkDeleteCounter();
  } catch (error) {
    console.error("Failed to load reports:", error);
    reportsListEl.innerHTML = `
      <div class="no-reports">
        Error loading reports:<br>
        <small>${error}</small>
      </div>`;
  }
}
// Debounced filter input for the reports panel
const reportsFilterInput = document.getElementById("reports-filter-input");
let reportsFilterTimeout = null;
reportsFilterInput.addEventListener("input", (e) => {
  clearTimeout(reportsFilterTimeout);
  reportsFilterTimeout = setTimeout(() => {
    reportsFilterQuery = e.target.value.trim();
    loadReportsList().catch(err => console.error("Failed to filter reports:", err));
  }, 300);
});