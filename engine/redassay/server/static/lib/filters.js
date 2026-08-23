// Client-side filtering, sorting and grouping. The server already ranks
// findings; this re-ranks a subset without another round trip, so typing in the
// search box stays instant on a few thousand findings.

import { severityRank } from "./format.js";

export const DEFAULT_FILTERS = Object.freeze({
  query: "",
  severities: [],      // empty means "all"
  statuses: ["open", "confirmed", "queued", "fixing"],
  sources: [],
  path: "",
  sort: "priority",
});

/** Substring match across the fields a reviewer would actually search. */
export function matchesQuery(finding, query) {
  if (!query) return true;
  const needle = query.toLowerCase().trim();
  if (!needle) return true;
  const haystack = [
    finding.title,
    finding.rule_id,
    finding.location && finding.location.path,
    finding.description,
    finding.id,
    (finding.cwe || []).join(" "),
    (finding.tags || []).join(" "),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return needle.split(/\s+/).every((term) => haystack.includes(term));
}

export function matchesFilters(finding, filters) {
  const f = { ...DEFAULT_FILTERS, ...(filters || {}) };
  if (f.severities.length && !f.severities.includes(finding.severity)) return false;
  if (f.statuses.length && !f.statuses.includes(finding.status)) return false;
  if (f.sources.length && !f.sources.includes(finding.source)) return false;
  if (f.path) {
    const path = (finding.location && finding.location.path) || "";
    if (!path.startsWith(f.path)) return false;
  }
  return matchesQuery(finding, f.query);
}

const SORTERS = {
  priority: (a, b) => (b.priority || 0) - (a.priority || 0) || comparePath(a, b),
  severity: (a, b) => severityRank(a.severity) - severityRank(b.severity) || comparePath(a, b),
  path: comparePath,
  recent: (a, b) => String(b.last_seen || "").localeCompare(String(a.last_seen || "")) || comparePath(a, b),
  rule: (a, b) => String(a.rule_id).localeCompare(String(b.rule_id)) || comparePath(a, b),
};

function comparePath(a, b) {
  const pathA = (a.location && a.location.path) || "";
  const pathB = (b.location && b.location.path) || "";
  return pathA.localeCompare(pathB) || ((a.location && a.location.line) || 0) - ((b.location && b.location.line) || 0);
}

export function applyFilters(findings, filters) {
  const f = { ...DEFAULT_FILTERS, ...(filters || {}) };
  const sorter = SORTERS[f.sort] || SORTERS.priority;
  return (findings || []).filter((finding) => matchesFilters(finding, f)).sort(sorter);
}

/** Counts per severity for the visible set, used by the filter chips. */
export function countBySeverity(findings) {
  const counts = {};
  for (const finding of findings || []) {
    counts[finding.severity] = (counts[finding.severity] || 0) + 1;
  }
  return counts;
}

/** Counts per scanner, for the "found by" facet. `claude` appears here too,
 *  which is the point: a reviewer often wants to read the model's findings
 *  separately from the deterministic ones. */
export function countBySource(findings) {
  const counts = {};
  for (const finding of findings || []) {
    counts[finding.source] = (counts[finding.source] || 0) + 1;
  }
  return counts;
}

export function countByStatus(findings) {
  const counts = {};
  for (const finding of findings || []) {
    counts[finding.status] = (counts[finding.status] || 0) + 1;
  }
  return counts;
}

export function groupByFile(findings) {
  const groups = new Map();
  for (const finding of findings || []) {
    const path = (finding.location && finding.location.path) || "(unknown)";
    if (!groups.has(path)) groups.set(path, []);
    groups.get(path).push(finding);
  }
  return [...groups.entries()]
    .map(([path, items]) => ({
      path,
      items,
      risk: items.reduce((total, item) => total + (item.priority || 0), 0),
    }))
    .sort((a, b) => b.risk - a.risk);
}

/** Toggle a value in a filter array without mutating the original. */
export function toggle(list, value) {
  const set = new Set(list || []);
  if (set.has(value)) set.delete(value);
  else set.add(value);
  return [...set];
}
