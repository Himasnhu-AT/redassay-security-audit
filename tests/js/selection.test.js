import { test } from "node:test";
import assert from "node:assert/strict";

import { Selection, describeBatch } from "../../engine/redassay/server/static/lib/selection.js";

const ordered = ["a", "b", "c", "d", "e"];

test("toggle adds and removes", () => {
  const sel = new Selection();
  sel.toggle("a");
  assert.ok(sel.has("a"));
  assert.equal(sel.size, 1);
  sel.toggle("a");
  assert.equal(sel.size, 0);
});

test("set replaces the whole selection", () => {
  const sel = new Selection(["a", "b"]);
  sel.set("c");
  assert.deepEqual(sel.toArray(), ["c"]);
});

test("extendTo selects an inclusive range in either direction", () => {
  const down = new Selection();
  down.set("b").extendTo("d", ordered);
  assert.deepEqual(down.toArray().sort(), ["b", "c", "d"]);

  const up = new Selection();
  up.set("d").extendTo("b", ordered);
  assert.deepEqual(up.toArray().sort(), ["b", "c", "d"]);
});

test("extendTo with no anchor selects just the target", () => {
  const sel = new Selection();
  sel.extendTo("c", ordered);
  assert.deepEqual(sel.toArray(), ["c"]);
});

test("extendTo ignores an id that is not visible", () => {
  const sel = new Selection();
  sel.set("a").extendTo("zzz", ordered);
  assert.deepEqual(sel.toArray(), ["a"]);
});

test("prune drops ids that filtering removed", () => {
  const sel = new Selection(["a", "b", "zzz"]);
  sel.anchor = "zzz";
  sel.prune(ordered);
  assert.deepEqual(sel.toArray().sort(), ["a", "b"]);
  assert.equal(sel.anchor, null);
});

test("selectAll accepts objects as well as ids", () => {
  const sel = new Selection();
  sel.selectAll([{ id: "x" }, { id: "y" }]);
  assert.deepEqual(sel.toArray().sort(), ["x", "y"]);
});

test("clear resets ids and anchor", () => {
  const sel = new Selection(["a"]);
  sel.anchor = "a";
  sel.clear();
  assert.equal(sel.size, 0);
  assert.equal(sel.anchor, null);
});

test("describeBatch summarizes severities and file spread", () => {
  const findings = [
    { id: "a", severity: "critical", location: { path: "x.py" } },
    { id: "b", severity: "high", location: { path: "x.py" } },
    { id: "c", severity: "high", location: { path: "y.py" } },
  ];
  assert.equal(
    describeBatch(findings, ["a", "b", "c"]),
    "3 findings (1 critical, 2 high) across 2 files"
  );
  assert.equal(describeBatch(findings, ["a"]), "1 finding (1 critical) across 1 file");
  assert.equal(describeBatch(findings, []), "Nothing selected");
});
