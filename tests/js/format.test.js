import { test } from "node:test";
import assert from "node:assert/strict";

import {
  escapeHtml,
  shortenPath,
  severityRank,
  relativeTime,
  pluralize,
  severitySummary,
  truncate,
  SEVERITY_ORDER,
} from "../../engine/redassay/server/static/lib/format.js";

test("escapeHtml neutralizes every injection character", () => {
  assert.equal(
    escapeHtml('<img src=x onerror="alert(1)">'),
    "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;"
  );
  assert.equal(escapeHtml("a & b"), "a &amp; b");
  assert.equal(escapeHtml("it's"), "it&#39;s");
});

test("escapeHtml handles null and undefined", () => {
  assert.equal(escapeHtml(null), "");
  assert.equal(escapeHtml(undefined), "");
  assert.equal(escapeHtml(0), "0");
});

test("escapeHtml is idempotent enough to be safe when applied twice", () => {
  const once = escapeHtml("<b>");
  assert.equal(escapeHtml(once), "&amp;lt;b&amp;gt;");
});

test("shortenPath keeps short paths untouched", () => {
  assert.equal(shortenPath("src/app.py"), "src/app.py");
});

test("shortenPath always preserves the filename", () => {
  const long = "a/very/deeply/nested/directory/structure/that/keeps/going/settings.py";
  const short = shortenPath(long, 40);
  assert.ok(short.length <= 41, `got ${short.length}: ${short}`);
  assert.ok(short.endsWith("settings.py"));
});

test("shortenPath survives a filename longer than the budget", () => {
  const short = shortenPath("dir/" + "x".repeat(80) + ".js", 30);
  assert.ok(short.length <= 31);
});

test("severityRank orders worst first and defaults unknown to medium", () => {
  const ranks = SEVERITY_ORDER.map(severityRank);
  assert.deepEqual(ranks, [...ranks].sort((a, b) => a - b));
  assert.equal(severityRank("nonsense"), severityRank("medium"));
});

test("relativeTime renders recent, singular and plural cases", () => {
  const now = Date.parse("2026-09-01T12:00:00Z");
  assert.equal(relativeTime("2026-09-01T11:59:50Z", now), "just now");
  assert.equal(relativeTime("2026-09-01T11:00:00Z", now), "1 hour ago");
  assert.equal(relativeTime("2026-09-01T09:00:00Z", now), "3 hours ago");
  assert.equal(relativeTime("2026-08-30T12:00:00Z", now), "2 days ago");
});

test("relativeTime returns empty for junk", () => {
  assert.equal(relativeTime(""), "");
  assert.equal(relativeTime("not a date"), "");
});

test("pluralize", () => {
  assert.equal(pluralize(1, "finding"), "1 finding");
  assert.equal(pluralize(3, "finding"), "3 findings");
  assert.equal(pluralize(2, "entry", "entries"), "2 entries");
});

test("severitySummary skips zero counts and keeps severity order", () => {
  assert.equal(
    severitySummary({ low: 2, critical: 1, high: 4, medium: 0 }),
    "1 critical · 4 high · 2 low"
  );
  assert.equal(severitySummary({}), "");
});

test("truncate collapses whitespace and adds an ellipsis", () => {
  assert.equal(truncate("a   b\n c", 20), "a b c");
  assert.equal(truncate("x".repeat(50), 10), "x".repeat(9) + "…");
});
