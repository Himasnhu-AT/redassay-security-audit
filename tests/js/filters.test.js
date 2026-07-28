import { test } from "node:test";
import assert from "node:assert/strict";

import {
  applyFilters,
  matchesQuery,
  matchesFilters,
  countBySeverity,
  countByStatus,
  groupByFile,
  toggle,
  DEFAULT_FILTERS,
} from "../../engine/redassay/server/static/lib/filters.js";

function finding(overrides = {}) {
  return {
    id: overrides.id || "abc123",
    title: "SQL query built from request data",
    rule_id: "py.sql-dynamic",
    severity: "high",
    status: "open",
    source: "python-ast",
    priority: 60,
    description: "A value from request.args reaches execute()",
    cwe: ["CWE-89"],
    tags: ["python"],
    last_seen: "2026-09-01T10:00:00Z",
    location: { path: "app/views.py", line: 42 },
    ...overrides,
  };
}

test("empty query matches everything", () => {
  assert.ok(matchesQuery(finding(), ""));
  assert.ok(matchesQuery(finding(), "   "));
});

test("query searches title, rule, path, cwe and id", () => {
  const f = finding();
  assert.ok(matchesQuery(f, "sql"));
  assert.ok(matchesQuery(f, "py.sql-dynamic"));
  assert.ok(matchesQuery(f, "views.py"));
  assert.ok(matchesQuery(f, "cwe-89"));
  assert.ok(matchesQuery(f, "abc123"));
  assert.ok(!matchesQuery(f, "kubernetes"));
});

test("all query terms must match", () => {
  const f = finding();
  assert.ok(matchesQuery(f, "sql views"));
  assert.ok(!matchesQuery(f, "sql kubernetes"));
});

test("default filters hide dismissed and fixed findings", () => {
  assert.ok(matchesFilters(finding({ status: "open" }), DEFAULT_FILTERS));
  assert.ok(!matchesFilters(finding({ status: "dismissed" }), DEFAULT_FILTERS));
  assert.ok(!matchesFilters(finding({ status: "verified" }), DEFAULT_FILTERS));
});

test("empty severity list means no severity filtering", () => {
  const items = [finding({ severity: "low" }), finding({ id: "b", severity: "critical" })];
  assert.equal(applyFilters(items, { severities: [] }).length, 2);
  assert.equal(applyFilters(items, { severities: ["critical"] }).length, 1);
});

test("path filter is a prefix match", () => {
  const items = [
    finding({ id: "a", location: { path: "app/views.py", line: 1 } }),
    finding({ id: "b", location: { path: "tests/test_views.py", line: 1 } }),
  ];
  const filtered = applyFilters(items, { path: "app/" });
  assert.equal(filtered.length, 1);
  assert.equal(filtered[0].id, "a");
});

test("priority sort puts the highest first, path breaks ties", () => {
  const items = [
    finding({ id: "a", priority: 10, location: { path: "z.py", line: 1 } }),
    finding({ id: "b", priority: 90, location: { path: "m.py", line: 1 } }),
    finding({ id: "c", priority: 90, location: { path: "a.py", line: 1 } }),
  ];
  assert.deepEqual(applyFilters(items, {}).map((f) => f.id), ["c", "b", "a"]);
});

test("severity sort ignores priority", () => {
  const items = [
    finding({ id: "a", severity: "low", priority: 99 }),
    finding({ id: "b", severity: "critical", priority: 1 }),
  ];
  assert.deepEqual(applyFilters(items, { sort: "severity" }).map((f) => f.id), ["b", "a"]);
});

test("recent sort is newest first", () => {
  const items = [
    finding({ id: "old", last_seen: "2026-01-01T00:00:00Z" }),
    finding({ id: "new", last_seen: "2026-09-01T00:00:00Z" }),
  ];
  assert.deepEqual(applyFilters(items, { sort: "recent" }).map((f) => f.id), ["new", "old"]);
});

test("applyFilters does not mutate the input array", () => {
  const items = [finding({ id: "a", priority: 1 }), finding({ id: "b", priority: 100 })];
  const before = items.map((f) => f.id);
  applyFilters(items, {});
  assert.deepEqual(items.map((f) => f.id), before);
});

test("counts", () => {
  const items = [
    finding({ severity: "high", status: "open" }),
    finding({ id: "b", severity: "high", status: "queued" }),
    finding({ id: "c", severity: "low", status: "open" }),
  ];
  assert.deepEqual(countBySeverity(items), { high: 2, low: 1 });
  assert.deepEqual(countByStatus(items), { open: 2, queued: 1 });
});

test("groupByFile orders files by summed risk", () => {
  const items = [
    finding({ id: "a", priority: 10, location: { path: "low.py", line: 1 } }),
    finding({ id: "b", priority: 50, location: { path: "hot.py", line: 1 } }),
    finding({ id: "c", priority: 40, location: { path: "hot.py", line: 9 } }),
  ];
  const groups = groupByFile(items);
  assert.equal(groups[0].path, "hot.py");
  assert.equal(groups[0].risk, 90);
  assert.equal(groups[0].items.length, 2);
});

test("toggle adds, removes and does not mutate", () => {
  const original = ["high"];
  assert.deepEqual(toggle(original, "low").sort(), ["high", "low"]);
  assert.deepEqual(toggle(original, "high"), []);
  assert.deepEqual(original, ["high"]);
});
