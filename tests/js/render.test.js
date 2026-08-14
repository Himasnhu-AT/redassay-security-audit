import { test } from "node:test";
import assert from "node:assert/strict";

import {
  findingRow,
  codeBlock,
  commentList,
  classification,
  isSafeUrl,
  headerCounts,
  severityChip,
  hotspotRow,
} from "../../engine/redassay/server/static/lib/render.js";

const XSS = '<img src=x onerror=alert(1)>';

function finding(overrides = {}) {
  return {
    id: "abc123",
    title: "SQL statement assembled at runtime",
    rule_id: "py.sql-dynamic",
    severity: "critical",
    status: "open",
    comments: [],
    cwe: ["CWE-89"],
    owasp: [],
    tags: [],
    references: [],
    location: { path: "app/views.py", line: 42 },
    ...overrides,
  };
}

// --- the security-relevant half ----------------------------------------
test("a hostile title cannot break out of the row", () => {
  const html = findingRow(finding({ title: XSS }));
  assert.ok(!html.includes("<img"));
  assert.ok(html.includes("&lt;img"));
});

test("a hostile path is escaped in both the body and the title attribute", () => {
  const html = findingRow(finding({ location: { path: `x"${XSS}`, line: 1 } }));
  assert.ok(!html.includes("<img"));
  assert.ok(!html.includes('title="x"<'));
});

test("a hostile rule id and status are escaped", () => {
  const html = findingRow(finding({ rule_id: XSS, status: '"><script>' }));
  assert.ok(!html.includes("<script"));
  assert.ok(!html.includes("<img"));
});

test("a hostile finding id cannot forge a data attribute", () => {
  const html = findingRow(finding({ id: '" onclick="evil()' }));
  assert.ok(!html.includes('onclick="evil()'));
  assert.ok(html.includes("&quot;"));
});

test("source lines are escaped - this is code from the repo under audit", () => {
  const html = codeBlock({ start_line: 1, lines: [`const a = "${XSS}";`] }, 1);
  assert.ok(!html.includes("<img"));
  assert.ok(html.includes("&lt;img"));
});

test("comment author and body are escaped", () => {
  const html = commentList([{ author: XSS, body: XSS, created_at: "2026-09-01T00:00:00Z" }]);
  assert.equal(html.includes("<img"), false);
});

test("classification tags are escaped", () => {
  const html = classification(finding({ tags: [XSS] }));
  assert.ok(!html.includes("<img"));
});

test("severity and hotspot helpers escape their input", () => {
  assert.ok(!severityChip(XSS, 3, false).includes("<img"));
  assert.ok(!hotspotRow({ path: XSS, count: 1 }).includes("<img"));
  assert.ok(!headerCounts({ [XSS]: 2 }).includes("<img"));
});

// --- reference links ----------------------------------------------------
test("only http and https become links", () => {
  assert.ok(isSafeUrl("https://github.com/advisories/GHSA-x"));
  assert.ok(isSafeUrl("http://example.com"));
  assert.ok(!isSafeUrl("javascript:alert(1)"));
  assert.ok(!isSafeUrl("data:text/html,<script>alert(1)</script>"));
  assert.ok(!isSafeUrl("  javascript:alert(1)"));
  assert.ok(!isSafeUrl(null));
});

test("a javascript: reference is dropped, not rendered", () => {
  const html = classification(finding({ references: ["javascript:alert(1)"], tags: ["x"] }));
  assert.ok(!html.includes("javascript:"));
});

test("a safe reference is rendered with noopener", () => {
  const html = classification(finding({ references: ["https://example.com/advisory"] }));
  assert.ok(html.includes('rel="noreferrer noopener"'));
  assert.ok(html.includes("https://example.com/advisory"));
});

// --- ordinary behaviour -------------------------------------------------
test("findingRow marks active and selected state", () => {
  assert.ok(findingRow(finding(), { active: true }).includes("active"));
  const selected = findingRow(finding(), { selected: true });
  assert.ok(selected.includes("selected"));
  assert.ok(selected.includes("checked"));
});

test("an open finding shows no status tag", () => {
  assert.ok(!findingRow(finding({ status: "open" })).includes("status-tag"));
  assert.ok(findingRow(finding({ status: "queued" })).includes("status-queued"));
});

test("note count is pluralized and hidden at zero", () => {
  assert.ok(!findingRow(finding()).includes("note"));
  assert.ok(findingRow(finding({ comments: [{}] })).includes("1&nbsp;note<"));
  assert.ok(findingRow(finding({ comments: [{}, {}] })).includes("2&nbsp;notes"));
});

test("the line number is appended only when present", () => {
  assert.ok(findingRow(finding()).includes(":42"));
  assert.ok(!findingRow(finding({ location: { path: "a.py", line: 0 } })).includes(":0"));
});

test("codeBlock marks the focus line and numbers from start_line", () => {
  const html = codeBlock({ start_line: 10, lines: ["a", "b", "c"] }, 11);
  assert.ok(html.includes('<span class="ln">10</span>'));
  assert.ok(html.includes('class="row hit"'));
  assert.equal((html.match(/class="row hit"/g) || []).length, 1);
});

test("codeBlock handles missing context", () => {
  assert.ok(codeBlock(null, 1).includes("not available"));
  assert.ok(codeBlock({ lines: [] }, 1).includes("not available"));
});

test("commentList handles the empty case", () => {
  assert.ok(commentList([]).includes("No notes yet"));
  assert.ok(commentList(null).includes("No notes yet"));
});

test("classification returns nothing when there is nothing to classify", () => {
  assert.equal(classification(finding({ cwe: [], owasp: [], tags: [], references: [] })), "");
});

test("headerCounts falls back when everything is clean", () => {
  assert.ok(headerCounts({}).includes("no open findings"));
});
