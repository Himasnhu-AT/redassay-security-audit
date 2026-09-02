// Filters in the URL hash.
//
// A board view is something people want to hand to someone else: "look at the
// criticals in app/billing". Keeping the filter state in the hash makes that a
// copyable link, makes the back button work, and means a reload does not throw
// away the filtering you just did.
//
// Encoded as a compact query string rather than JSON so the URL stays readable:
//   #sev=critical,high&status=open&path=app/&sort=severity&q=sql

import { DEFAULT_FILTERS } from "./filters.js";

const KEYS = {
  sev: "severities",
  status: "statuses",
  src: "sources",
  path: "path",
  sort: "sort",
  q: "query",
};

const LIST_FIELDS = new Set(["severities", "statuses", "sources"]);

/** Filters -> hash string (without the leading "#"). Defaults are omitted. */
export function encode(filters) {
  const parts = [];
  for (const [key, field] of Object.entries(KEYS)) {
    const value = filters[field];
    const fallback = DEFAULT_FILTERS[field];
    if (LIST_FIELDS.has(field)) {
      if (!value || !value.length) continue;
      if (sameSet(value, fallback)) continue;
      parts.push(`${key}=${value.map(encodeURIComponent).join(",")}`);
    } else {
      if (!value || value === fallback) continue;
      parts.push(`${key}=${encodeURIComponent(value)}`);
    }
  }
  return parts.join("&");
}

/** Hash string -> partial filters. Unknown keys are ignored. */
export function decode(hash) {
  const filters = {};
  const body = String(hash || "").replace(/^#/, "");
  if (!body) return filters;
  for (const chunk of body.split("&")) {
    if (!chunk) continue;
    const index = chunk.indexOf("=");
    if (index === -1) continue;
    const key = chunk.slice(0, index);
    const raw = chunk.slice(index + 1);
    const field = KEYS[key];
    if (!field) continue;
    if (LIST_FIELDS.has(field)) {
      filters[field] = raw
        .split(",")
        .filter(Boolean)
        .map((value) => safeDecode(value));
    } else {
      filters[field] = safeDecode(raw);
    }
  }
  return filters;
}

/** Merge decoded filters over the defaults. */
export function apply(hash, base = DEFAULT_FILTERS) {
  return { ...base, ...decode(hash) };
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;          // a hand-edited URL should not break the page
  }
}

function sameSet(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
  const other = new Set(b);
  return a.every((value) => other.has(value));
}
