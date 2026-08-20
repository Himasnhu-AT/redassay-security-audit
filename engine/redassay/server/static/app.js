// Board wiring. Everything testable lives in ./lib; this file is the part that
// needs a DOM, kept thin on purpose.

import { escapeHtml, relativeTime, severitySummary } from "./lib/format.js";
import {
  classification, codeBlock, commentList, findingRow, headerCounts, hotspotRow, severityChip,
} from "./lib/render.js";
import { applyFilters, countBySeverity, countByStatus, toggle, DEFAULT_FILTERS } from "./lib/filters.js";
import { Selection, describeBatch } from "./lib/selection.js";

const STATUS_CHOICES = ["open", "confirmed", "queued", "fixing", "fixed", "verified", "dismissed"];
const SORT_CHOICES = [
  ["priority", "risk"],
  ["severity", "severity"],
  ["path", "file"],
  ["recent", "recent"],
  ["rule", "rule"],
];
const POLL_MS = 2500;

const state = {
  findings: [],
  visible: [],
  hotspots: [],
  queue: { pending: [], claimed: [], stats: {} },
  stats: {},
  repo: "",
  filters: { ...DEFAULT_FILTERS },
  selection: new Selection(),
  activeId: null,
  detail: null,
  lastSignature: "",
};

const el = (id) => document.getElementById(id);

// --- data ---------------------------------------------------------------
async function api(path, options = {}) {
  const init = { headers: { "Content-Type": "application/json" }, ...options };
  if (init.body && typeof init.body !== "string") init.body = JSON.stringify(init.body);
  const response = await fetch(path, init);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
  return payload;
}

async function refresh({ force = false } = {}) {
  const data = await api("/api/state");
  const signature = JSON.stringify([data.stats, data.queue.stats, data.findings.length,
    data.findings.map((f) => f.status + f.comments.length).join("")]);
  // redassay: ignore crypto.constant-time-compare - a render-skip fingerprint, not a secret
  if (!force && signature === state.lastSignature) return;
  state.lastSignature = signature;
  state.findings = data.findings;
  state.hotspots = data.hotspots;
  state.queue = data.queue;
  state.stats = data.stats;
  state.repo = data.repo;
  render();
}

// --- rendering ----------------------------------------------------------
function render() {
  el("repo-name").textContent = state.repo;
  renderHeaderCounts();
  renderFacets();
  renderHotspots();
  renderList();
  renderQueuePill();
}

function renderHeaderCounts() {
  // redassay: ignore xss.innerhtml-assignment - headerCounts() escapes, see lib/render.js
  el("header-counts").innerHTML = headerCounts(countBySeverity(state.findings.filter((f) => f.is_open)));
}

function renderFacets() {
  const severityCounts = countBySeverity(state.findings);
  // redassay: ignore xss.innerhtml-assignment - severityChip() escapes, see lib/render.js
  el("facet-severity").innerHTML = ["critical", "high", "medium", "low", "info"]
    .map((name) => severityChip(name, severityCounts[name] || 0, state.filters.severities.includes(name)))
    .join("");

  const statusCounts = countByStatus(state.findings);
  // redassay: ignore xss.innerhtml-assignment - STATUS_CHOICES is a module constant
  el("facet-status").innerHTML = STATUS_CHOICES
    .map((name) => chip(name, statusCounts[name] || 0, state.filters.statuses.includes(name), "status"))
    .join("");

  // redassay: ignore xss.innerhtml-assignment - SORT_CHOICES is a module constant
  el("facet-sort").innerHTML = SORT_CHOICES
    .map(([value, label]) =>
      `<button class="chip ${state.filters.sort === value ? "on" : ""}" data-facet="sort" data-value="${value}">${label}</button>`
    )
    .join("");
}

function chip(name, count, active, facet) {
  return `<button class="chip ${active ? "on" : ""}" data-facet="${facet}" data-value="${name}">` +
    `${name}<span class="n">${count}</span></button>`;
}

function renderHotspots() {
  // redassay: ignore xss.innerhtml-assignment - hotspotRow() escapes, see lib/render.js
  el("hotspots").innerHTML = state.hotspots.map(hotspotRow).join("");
}

function renderList() {
  state.visible = applyFilters(state.findings, state.filters);
  state.selection.prune(state.visible);

  el("list-count").textContent = `${state.visible.length} finding${state.visible.length === 1 ? "" : "s"}`;
  el("empty").hidden = state.visible.length > 0;
  el("select-all").checked = state.visible.length > 0 && state.selection.size === state.visible.length;

  const chosen = state.selection.size;
  el("selection-note").textContent = chosen ? `${chosen} selected` : "";
  const fixButton = el("btn-fix");
  fixButton.disabled = chosen === 0;
  fixButton.textContent = chosen ? `Fix ${chosen} selected` : "Fix selected";

  renderBatchBar();
  el("findings").innerHTML = state.visible
    .map((finding) => findingRow(finding, {
      active: finding.id === state.activeId,
      selected: state.selection.has(finding.id),
    }))
    .join("");
  if (state.activeId && !state.visible.some((f) => f.id === state.activeId)) {
    state.activeId = null;
    renderDetail(null);
  }
}

function renderQueuePill() {
  const pending = (state.queue.pending || []).length;
  const claimed = (state.queue.claimed || []).length;
  const pill = el("queue-pill");
  if (!pending && !claimed) {
    pill.hidden = true;
    return;
  }
  pill.hidden = false;
  pill.textContent = claimed
    ? `${claimed} in progress`
    : `${pending} queued for the agent`;
}

async function openFinding(id) {
  closePanels();
  state.activeId = id;
  renderList();
  try {
    state.detail = await api(`/api/findings/${id}`);
    renderDetail(state.detail);
  } catch (error) {
    toast(error.message, true);
  }
}

function renderDetail(finding) {
  const pane = el("detail");
  if (!finding) {
    pane.innerHTML = `<div class="detail-empty"><p>Select a finding.</p></div>`;
    return;
  }
  const loc = finding.location || {};
  pane.innerHTML = `<div class="detail">
    <h1>${escapeHtml(finding.title)}</h1>
    <div class="detail-meta">
      <span class="sev sev-${finding.severity}">${finding.severity}</span>
      <span>confidence ${escapeHtml(finding.confidence)}</span>
      <span>${escapeHtml(finding.rule_id)}</span>
      <span>${escapeHtml(finding.id)}</span>
      <span>${escapeHtml(finding.source)}</span>
      <span class="status-tag status-${finding.status}">${finding.status}</span>
      <span>${escapeHtml(relativeTime(finding.last_seen))}</span>
    </div>

    <div class="detail-actions">
      <button class="btn btn-primary btn-small" data-act="fix">Request fix</button>
      <button class="btn btn-small" data-act="confirm">Confirm</button>
      <button class="btn btn-small btn-danger" data-act="dismiss">Dismiss</button>
      ${finding.status === "dismissed" ? `<button class="btn btn-small" data-act="reopen">Reopen</button>` : ""}
    </div>

    <form class="inline-panel" data-panel="fix" hidden>
      <label for="fix-note">Anything the fix must preserve? (optional)</label>
      <textarea id="fix-note" name="note" rows="2" placeholder="Keep the --verbose flag working"></textarea>
      <div class="row">
        <button class="btn btn-small" type="button" data-cancel="fix">Cancel</button>
        <button class="btn btn-primary btn-small" type="submit">Queue the fix</button>
      </div>
    </form>

    <form class="inline-panel" data-panel="dismiss" hidden>
      <label for="dismiss-reason">Why is this not worth fixing?</label>
      <textarea id="dismiss-reason" name="reason" rows="2" placeholder="The argument is a module constant, never request data"></textarea>
      <label class="checkbox"><input type="checkbox" name="suppress_rule"> also stop reporting this rule for this file</label>
      <div class="row">
        <button class="btn btn-small" type="button" data-cancel="dismiss">Cancel</button>
        <button class="btn btn-danger btn-small" type="submit">Dismiss</button>
      </div>
    </form>

    ${finding.description ? `<h3>What it is</h3><p>${escapeHtml(finding.description)}</p>` : ""}

    <h3>${escapeHtml(loc.path || "")}${loc.line ? ":" + loc.line : ""}</h3>
    ${codeBlock(finding.context, loc.line)}

    ${finding.remediation ? `<h3>How to fix</h3><div class="remediation">${escapeHtml(finding.remediation)}</div>` : ""}

    ${classification(finding)}

    <h3>Notes</h3>
    ${commentList(finding.comments)}
    <form class="comment-form" data-form="comment">
      <textarea name="body" placeholder="Why is this a false positive? What should the fix preserve?"></textarea>
      <div class="row"><button class="btn btn-small" type="submit">Add note</button></div>
    </form>
  </div>`;
}

// --- actions ------------------------------------------------------------
async function act(id, action, body = {}) {
  try {
    await api(`/api/findings/${id}/${action}`, { method: "POST", body });
    await refresh({ force: true });
    if (state.activeId === id) await openFinding(id);
    return true;
  } catch (error) {
    toast(error.message, true);
    return false;
  }
}

/** Reveal one of the detail pane's inline panels. Modal dialogs (prompt,
 *  confirm) block the whole page and lose what you typed if you mis-click, so
 *  the board asks for the note in place instead. */
function openPanel(name) {
  for (const panel of document.querySelectorAll("[data-panel]")) {
    panel.hidden = panel.dataset.panel !== name;
  }
  const active = document.querySelector(`[data-panel="${name}"]`);
  if (active) active.querySelector("textarea").focus();
}

function closePanels() {
  for (const panel of document.querySelectorAll("[data-panel]")) panel.hidden = true;
}

async function submitFix(id, note) {
  closePanels();
  if (await act(id, "fix", { note })) toast("Queued for the agent");
}

async function submitDismiss(id, reason, suppressRule) {
  if (!reason.trim()) {
    toast("A reason is required - the next person needs to know why", true);
    return;
  }
  closePanels();
  if (await act(id, "dismiss", { reason, suppress_rule: suppressRule })) toast("Dismissed");
}

function renderBatchBar() {
  const bar = el("batch-bar");
  const ids = state.selection.toArray();
  if (!ids.length) {
    bar.hidden = true;
    return;
  }
  bar.hidden = false;
  el("batch-summary").textContent = describeBatch(state.findings, ids);
}

async function fixSelected() {
  const ids = state.selection.toArray();
  if (!ids.length) return;
  try {
    await api("/api/fix", { method: "POST", body: { finding_ids: ids } });
    state.selection.clear();
    await refresh({ force: true });
    toast(`Queued ${ids.length} for the agent`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function rescan() {
  try {
    await api("/api/rescan", { method: "POST", body: {} });
    await refresh({ force: true });
    toast("Rescan requested - the agent will pick it up");
  } catch (error) {
    toast(error.message, true);
  }
}

async function showExport(format = "markdown") {
  try {
    const payload = await api(`/api/report?format=${encodeURIComponent(format)}`);
    el("export-title").textContent = `${payload.filename} - ${payload.count} findings`;
    el("export-body").value = payload.body;
    el("export-sheet").hidden = false;
    const textarea = el("export-body");
    textarea.focus();
    // Focusing a readonly textarea lands the caret at the end, which shows the
    // reader the last finding in the report rather than the first.
    textarea.setSelectionRange(0, 0);
    textarea.scrollTop = 0;
  } catch (error) {
    toast(error.message, true);
  }
}

function hideExport() {
  el("export-sheet").hidden = true;
}

async function copyExport() {
  const textarea = el("export-body");
  textarea.select();
  try {
    await navigator.clipboard.writeText(textarea.value);
    toast("Copied");
  } catch {
    // Clipboard access can be refused; the text is selected either way.
    toast("Selected - press the copy shortcut", true);
  }
}

let toastTimer = null;
function toast(message, isError = false) {
  const node = el("toast");
  node.textContent = message;
  node.className = isError ? "toast error" : "toast";
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    node.hidden = true;
  }, 3200);
}

// --- events -------------------------------------------------------------
function wire() {
  el("search").addEventListener("input", (event) => {
    state.filters.query = event.target.value;
    renderList();
  });

  document.querySelector(".sidebar").addEventListener("click", (event) => {
    const chipEl = event.target.closest("[data-facet]");
    if (chipEl) {
      const { facet, value } = chipEl.dataset;
      if (facet === "sort") state.filters.sort = value;
      if (facet === "severity") state.filters.severities = toggle(state.filters.severities, value);
      if (facet === "status") state.filters.statuses = toggle(state.filters.statuses, value);
      renderFacets();
      renderList();
      return;
    }
    const spot = event.target.closest("[data-path]");
    if (spot) {
      state.filters.path = state.filters.path === spot.dataset.path ? "" : spot.dataset.path;
      renderList();
      toast(state.filters.path ? `Filtered to ${state.filters.path}` : "Path filter cleared");
    }
  });

  el("findings").addEventListener("click", (event) => {
    const check = event.target.closest("[data-check]");
    if (check) {
      event.stopPropagation();
      if (event.shiftKey) state.selection.extendTo(check.dataset.check, state.visible);
      else state.selection.toggle(check.dataset.check);
      renderList();
      return;
    }
    const row = event.target.closest(".finding");
    if (row) openFinding(row.dataset.id);
  });

  el("select-all").addEventListener("change", (event) => {
    if (event.target.checked) state.selection.selectAll(state.visible);
    else state.selection.clear();
    renderList();
  });

  el("btn-fix").addEventListener("click", fixSelected);
  el("batch-confirm").addEventListener("click", fixSelected);
  el("batch-cancel").addEventListener("click", () => {
    state.selection.clear();
    renderList();
  });
  el("btn-rescan").addEventListener("click", rescan);
  el("btn-export").addEventListener("click", () => showExport("markdown"));
  el("export-close").addEventListener("click", hideExport);
  el("export-copy").addEventListener("click", copyExport);
  el("export-sheet").addEventListener("click", (event) => {
    if (event.target.id === "export-sheet") hideExport();
    const button = event.target.closest("[data-export]");
    if (button) showExport(button.dataset.export);
  });

  el("detail").addEventListener("click", (event) => {
    const button = event.target.closest("[data-act]");
    if (!button || !state.activeId) return;
    const action = button.dataset.act;
    if (action === "fix" || action === "dismiss") openPanel(action);
    if (action === "confirm") act(state.activeId, "status", { status: "confirmed" });
    if (action === "reopen") act(state.activeId, "reopen");
  });

  el("detail").addEventListener("click", (event) => {
    if (event.target.closest("[data-cancel]")) closePanels();
  });

  el("detail").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!state.activeId) return;
    const form = event.target;
    const textarea = form.querySelector("textarea");

    if (form.dataset.form === "comment") {
      const body = textarea.value.trim();
      if (!body) return;
      textarea.value = "";
      if (await act(state.activeId, "comment", { body })) toast("Note added");
      return;
    }
    if (form.dataset.panel === "fix") {
      await submitFix(state.activeId, textarea.value.trim());
      return;
    }
    if (form.dataset.panel === "dismiss") {
      const suppress = form.querySelector("[name=suppress_rule]").checked;
      await submitDismiss(state.activeId, textarea.value, suppress);
    }
  });

  document.addEventListener("keydown", (event) => {
    const typing = ["INPUT", "TEXTAREA"].includes(event.target.tagName);
    if (event.key === "/" && !typing) {
      event.preventDefault();
      el("search").focus();
      return;
    }
    if (event.key === "Escape") {
      hideExport();
      closePanels();
      if (typing) event.target.blur();
      return;
    }
    if (typing) return;

    const index = state.visible.findIndex((f) => f.id === state.activeId);
    if (event.key === "j" || event.key === "ArrowDown") {
      event.preventDefault();
      const next = state.visible[Math.min(index + 1, state.visible.length - 1)] || state.visible[0];
      if (next) openFinding(next.id);
    } else if (event.key === "k" || event.key === "ArrowUp") {
      event.preventDefault();
      const prev = state.visible[Math.max(index - 1, 0)];
      if (prev) openFinding(prev.id);
    } else if (event.key === "x" && state.activeId) {
      state.selection.toggle(state.activeId);
      renderList();
    } else if (event.key === "f" && state.activeId) {
      openPanel("fix");
    } else if (event.key === "d" && state.activeId) {
      openPanel("dismiss");
    } else if (event.key === "c" && state.activeId) {
      const textarea = document.querySelector(".comment-form textarea");
      if (textarea) textarea.focus();
    }
  });
}

wire();
refresh({ force: true }).catch((error) => toast(error.message, true));
setInterval(() => refresh().catch(() => {}), POLL_MS);
