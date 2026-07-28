// Formatting helpers. Pure functions, no DOM - so they can be unit tested in
// node without a browser or a build step.

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_RANK = SEVERITY_ORDER.reduce((acc, name, index) => {
  acc[name] = index;
  return acc;
}, {});

/** Escape text for insertion into HTML. The board renders scanner output -
 *  including attacker-controlled snippets from the repo under audit - so this
 *  is load-bearing, not decoration. */
export function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Shorten a path for a narrow list column, keeping the filename intact. */
export function shortenPath(path, maxLength = 48) {
  if (!path) return "";
  if (path.length <= maxLength) return path;
  const parts = path.split("/");
  const file = parts.pop();
  if (file.length >= maxLength - 3) return "…" + file.slice(-(maxLength - 1));
  let head = "";
  for (const part of parts) {
    if (head.length + part.length + 1 > maxLength - file.length - 4) break;
    head += part + "/";
  }
  return head + "…/" + file;
}

export function severityRank(severity) {
  const rank = SEVERITY_RANK[severity];
  return rank === undefined ? SEVERITY_RANK.medium : rank;
}

/** "3 minutes ago". Takes an ISO string; returns "" for anything unparseable. */
export function relativeTime(iso, now = Date.now()) {
  if (!iso) return "";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "";
  const seconds = Math.round((now - then) / 1000);
  if (seconds < 45) return "just now";
  const units = [
    ["year", 31557600],
    ["month", 2629800],
    ["week", 604800],
    ["day", 86400],
    ["hour", 3600],
    ["minute", 60],
  ];
  for (const [label, size] of units) {
    if (seconds >= size) {
      const count = Math.round(seconds / size);
      return `${count} ${label}${count === 1 ? "" : "s"} ago`;
    }
  }
  return "just now";
}

export function pluralize(count, singular, plural) {
  return `${count} ${count === 1 ? singular : plural || singular + "s"}`;
}

/** Compact counts like "3 critical · 7 high" for the header. */
export function severitySummary(counts) {
  return SEVERITY_ORDER
    .filter((name) => counts && counts[name])
    .map((name) => `${counts[name]} ${name}`)
    .join(" · ");
}

export function truncate(text, limit = 140) {
  if (!text) return "";
  const flat = String(text).replace(/\s+/g, " ").trim();
  return flat.length <= limit ? flat : flat.slice(0, limit - 1) + "…";
}
