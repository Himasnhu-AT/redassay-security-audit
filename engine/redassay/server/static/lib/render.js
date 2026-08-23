// HTML construction for the board.
//
// Pulled out of app.js because this is where the escaping lives, and escaping
// is the one thing in the board that is actually security-relevant: every
// finding carries a snippet copied verbatim out of the repository under audit,
// which is attacker-controlled by construction. A stored XSS in a tool people
// point at hostile code would be an embarrassing way to lose.
//
// No DOM access here - these return strings, so node can test them.

import { escapeHtml, shortenPath, relativeTime, truncate } from "./format.js";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

/** One row in the findings list. */
export function findingRow(finding, { active = false, selected = false } = {}) {
  const location = finding.location || {};
  const path = location.path || "";
  const line = location.line || 0;
  const classes = ["finding", active ? "active" : "", selected ? "selected" : ""]
    .filter(Boolean)
    .join(" ");
  const noteCount = (finding.comments || []).length;

  return `<li class="${classes}" data-id="${escapeHtml(finding.id)}">
    <input type="checkbox" data-check="${escapeHtml(finding.id)}" ${selected ? "checked" : ""}>
    <div>
      <div class="title">${escapeHtml(finding.title)}</div>
      <div class="meta">
        <span class="sev sev-${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
        <span class="path" title="${escapeHtml(path)}">${escapeHtml(shortenPath(path, 42))}${line ? ":" + line : ""}</span>
        <span>${escapeHtml(finding.rule_id)}</span>
        ${finding.status && finding.status !== "open"
          ? `<span class="status-tag status-${escapeHtml(finding.status)}">${escapeHtml(finding.status)}</span>`
          : ""}
        ${noteCount ? `<span>${noteCount}&nbsp;note${noteCount === 1 ? "" : "s"}</span>` : ""}
      </div>
    </div>
  </li>`;
}

/** The source context block, with the flagged line marked. */
export function codeBlock(context, focusLine) {
  if (!context || !Array.isArray(context.lines) || !context.lines.length) {
    return `<p class="muted">Source not available.</p>`;
  }
  const rows = context.lines.map((line, index) => {
    const number = (context.start_line || 1) + index;
    const hit = number === focusLine ? " hit" : "";
    return `<div class="row${hit}"><span class="ln">${number}</span><span class="src">${escapeHtml(line)}</span></div>`;
  });
  return `<div class="code">${rows.join("")}</div>`;
}

export function commentList(comments) {
  if (!comments || !comments.length) return `<p class="muted">No notes yet.</p>`;
  const items = comments.map(
    (comment) => `<li class="comment">
        <div class="who">${escapeHtml(comment.author)} · ${escapeHtml(relativeTime(comment.created_at))}</div>
        <div class="body">${escapeHtml(comment.body)}</div>
      </li>`
  );
  return `<ul class="comments">${items.join("")}</ul>`;
}

export function classification(finding) {
  const tags = [...(finding.cwe || []), ...(finding.owasp || []), ...(finding.tags || [])];
  const references = finding.references || [];
  if (!tags.length && !references.length) return "";
  const chips = tags.map((tag) => `<span class="tag">${escapeHtml(tag)}</span>`).join("");
  const links = references
    .filter(isSafeUrl)
    .map(
      (url) =>
        `<p><a href="${escapeHtml(url)}" target="_blank" rel="noreferrer noopener">${escapeHtml(truncate(url, 80))}</a></p>`
    )
    .join("");
  return `<h3>Classification</h3><div class="tags">${chips}</div>${links}`;
}

/** Only http(s) becomes a link. A reference is data from a rule pack, and a
 *  javascript: URL in one would be a script-execution primitive. */
export function isSafeUrl(url) {
  if (typeof url !== "string") return false;
  return /^https?:\/\//i.test(url.trim());
}

export function headerCounts(counts) {
  const parts = SEVERITIES.filter((name) => counts && counts[name]).map(
    (name) =>
      `<span class="count"><span class="dot" style="background:var(--${name})"></span>${counts[name]} ${escapeHtml(name)}</span>`
  );
  return parts.join("") || `<span class="count">no open findings</span>`;
}

export function severityChip(name, count, active) {
  return (
    `<button class="chip ${active ? "on" : ""}" data-facet="severity" data-value="${escapeHtml(name)}">` +
    `${escapeHtml(name)}<span class="n">${count}</span></button>`
  );
}

/** A facet chip for any facet. Keeps the escaping in one place. */
export function facetChip(facet, value, count, active, label = null) {
  return (
    `<button class="chip ${active ? "on" : ""}" data-facet="${escapeHtml(facet)}" ` +
    `data-value="${escapeHtml(value)}">${escapeHtml(label || value)}` +
    (count === null ? "" : `<span class="n">${count}</span>`) +
    `</button>`
  );
}

export function hotspotRow(spot) {
  return (
    `<li data-path="${escapeHtml(spot.path)}" title="${escapeHtml(spot.path)}">` +
    `<span>${escapeHtml(shortenPath(spot.path, 24))}</span>` +
    `<span class="risk">${spot.count}</span></li>`
  );
}
