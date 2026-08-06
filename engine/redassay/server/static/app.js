// Board wiring. Everything testable lives in ./lib; this file is the part that
// needs a DOM, kept thin on purpose.

import { escapeHtml, shortenPath, relativeTime, severitySummary, truncate } from "./lib/format.js";
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
  const counts = countBySeverity(state.findings.filter((f) => f.is_open));
  // redassay: ignore xss.innerhtml-assignment - severity names are a fixed vocabulary, counts are integers
  el("header-counts").innerHTML = ["critical", "high", "medium", "low", "info"]
    .filter((name) => counts[name])
    .map((name) =>
      `<span class="count"><span class="dot" style="background:var(--${name})"></span>${counts[name]} ${name}</span>`
    )
    .join("") || `<span class="count">no open findings</span>`;
}

function renderFacets() {
  const severityCounts = countBySeverity(state.findings);
  // redassay: ignore xss.innerhtml-assignment - chip() interpolates only names from SEVERITY_ORDER and integer counts
  el("facet-severity").innerHTML = ["critical", "high", "medium", "low", "info"]
    .map((name) => chip(name, severityCounts[name] || 0, state.filters.severities.includes(name), "severity"))
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
  el("hotspots").innerHTML = state.hotspots
    .map((spot) =>
      `<li data-path="${escapeHtml(spot.path)}" title="${escapeHtml(spot.path)}">` +
      `<span>${escapeHtml(shortenPath(spot.path, 24))}</span>` +
      `<span class="risk">${spot.count}</span></li>`
    )
    .join("");
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

  el("findings").innerHTML = state.visible.map(renderRow).join("");
  if (state.activeId && !state.visible.some((f) => f.id === state.activeId)) {
    state.activeId = null;
    renderDetail(null);
  }
}

function renderRow(finding) {
  const path = (finding.location && finding.location.path) || "";
  const line = (finding.location && finding.location.line) || 0;
  const classes = [
    "finding",
    finding.id === state.activeId ? "active" : "",
    state.selection.has(finding.id) ? "selected" : "",
  ].join(" ");
  return `<li class="${classes}" data-id="${finding.id}">
    <input type="checkbox" data-check="${finding.id}" ${state.selection.has(finding.id) ? "checked" : ""}>
    <div>
      <div class="title">${escapeHtml(finding.title)}</div>
      <div class="meta">
        <span class="sev sev-${finding.severity}">${finding.severity}</span>
        <span class="path" title="${escapeHtml(path)}">${escapeHtml(shortenPath(path, 42))}${line ? ":" + line : ""}</span>
        <span>${escapeHtml(finding.rule_id)}</span>
        ${finding.status !== "open" ? `<span class="status-tag status-${finding.status}">${finding.status}</span>` : ""}
        ${finding.comments.length ? `<span>${finding.comments.length}&nbsp;note${finding.comments.length === 1 ? "" : "s"}</span>` : ""}
      </div>
    </div>
  </li>`;
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

    ${finding.description ? `<h3>What it is</h3><p>${escapeHtml(finding.description)}</p>` : ""}

    <h3>${escapeHtml(loc.path || "")}${loc.line ? ":" + loc.line : ""}</h3>
    ${renderCode(finding.context, loc.line)}

    ${finding.remediation ? `<h3>How to fix</h3><div class="remediation">${escapeHtml(finding.remediation)}</div>` : ""}

    ${renderReferences(finding)}

    <h3>Notes</h3>
    ${renderComments(finding.comments)}
    <form class="comment-form" data-form="comment">
      <textarea name="body" placeholder="Why is this a false positive? What should the fix preserve?"></textarea>
      <div class="row"><button class="btn btn-small" type="submit">Add note</button></div>
    </form>
  </div>`;
}

function renderCode(context, focusLine) {
  if (!context || !context.lines || !context.lines.length) {
    return `<p class="muted">Source not available.</p>`;
  }
  const rows = context.lines.map((line, index) => {
    const number = context.start_line + index;
    const hit = number === focusLine ? " hit" : "";
    return `<div class="row${hit}"><span class="ln">${number}</span><span class="src">${escapeHtml(line)}</span></div>`;
  });
  return `<div class="code">${rows.join("")}</div>`;
}

function renderReferences(finding) {
  const tags = [...(finding.cwe || []), ...(finding.owasp || []), ...(finding.tags || [])];
  if (!tags.length && !(finding.references || []).length) return "";
  const chips = tags.map((tag) => `<span class="tag">${escapeHtml(tag)}</span>`).join("");
  const links = (finding.references || [])
    .map((url) => `<p><a href="${escapeHtml(url)}" target="_blank" rel="noreferrer noopener">${escapeHtml(truncate(url, 80))}</a></p>`)
    .join("");
  return `<h3>Classification</h3><div class="tags">${chips}</div>${links}`;
}

function renderComments(comments) {
  if (!comments || !comments.length) return `<p class="muted">No notes yet.</p>`;
  return `<ul class="comments">${comments
    .map(
      (comment) => `<li class="comment">
        <div class="who">${escapeHtml(comment.author)} · ${escapeHtml(relativeTime(comment.created_at))}</div>
        <div class="body">${escapeHtml(comment.body)}</div>
      </li>`
    )
    .join("")}</ul>`;
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

async function requestFix(id) {
  const note = window.prompt("Anything the fix must preserve? (optional)");
  if (note === null) return;
  if (await act(id, "fix", { note })) toast("Queued for the agent");
}

async function dismiss(id) {
  const reason = window.prompt("Why is this not worth fixing?");
  if (reason === null) return;
  if (await act(id, "dismiss", { reason })) toast("Dismissed");
}

async function fixSelected() {
  const ids = state.selection.toArray();
  if (!ids.length) return;
  const summary = describeBatch(state.findings, ids);
  if (!window.confirm(`Queue ${summary} for the agent to fix?`)) return;
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
  el("btn-rescan").addEventListener("click", rescan);

  el("detail").addEventListener("click", (event) => {
    const button = event.target.closest("[data-act]");
    if (!button || !state.activeId) return;
    const action = button.dataset.act;
    if (action === "fix") requestFix(state.activeId);
    if (action === "dismiss") dismiss(state.activeId);
    if (action === "confirm") act(state.activeId, "status", { status: "confirmed" });
    if (action === "reopen") act(state.activeId, "reopen");
  });

  el("detail").addEventListener("submit", async (event) => {
    if (event.target.dataset.form !== "comment") return;
    event.preventDefault();
    const textarea = event.target.querySelector("textarea");
    const body = textarea.value.trim();
    if (!body || !state.activeId) return;
    textarea.value = "";
    if (await act(state.activeId, "comment", { body })) toast("Note added");
  });

  document.addEventListener("keydown", (event) => {
    const typing = ["INPUT", "TEXTAREA"].includes(event.target.tagName);
    if (event.key === "/" && !typing) {
      event.preventDefault();
      el("search").focus();
      return;
    }
    if (event.key === "Escape" && typing) {
      event.target.blur();
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
      requestFix(state.activeId);
    } else if (event.key === "d" && state.activeId) {
      dismiss(state.activeId);
    } else if (event.key === "c" && state.activeId) {
      const textarea = document.querySelector(".comment-form textarea");
      if (textarea) textarea.focus();
    }
  });
}

wire();
refresh({ force: true }).catch((error) => toast(error.message, true));
setInterval(() => refresh().catch(() => {}), POLL_MS);
