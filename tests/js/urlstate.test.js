import { test } from "node:test";
import assert from "node:assert/strict";

import { encode, decode, apply } from "../../engine/redassay/server/static/lib/urlstate.js";
import { DEFAULT_FILTERS } from "../../engine/redassay/server/static/lib/filters.js";

test("default filters encode to an empty hash", () => {
  assert.equal(encode({ ...DEFAULT_FILTERS }), "");
});

test("a severity selection round-trips", () => {
  const filters = { ...DEFAULT_FILTERS, severities: ["critical", "high"] };
  assert.deepEqual(decode(encode(filters)).severities, ["critical", "high"]);
});

test("statuses are omitted when they match the default set, order aside", () => {
  const reordered = { ...DEFAULT_FILTERS, statuses: [...DEFAULT_FILTERS.statuses].reverse() };
  assert.equal(encode(reordered), "");
});

test("a changed status set is encoded", () => {
  assert.equal(encode({ ...DEFAULT_FILTERS, statuses: ["dismissed"] }), "status=dismissed");
});

test("scalar fields round-trip", () => {
  const filters = { ...DEFAULT_FILTERS, path: "app/billing/", sort: "severity", query: "sql injection" };
  const decoded = decode(encode(filters));
  assert.equal(decoded.path, "app/billing/");
  assert.equal(decoded.sort, "severity");
  assert.equal(decoded.query, "sql injection");
});

test("values are percent-encoded so separators survive", () => {
  const hash = encode({ ...DEFAULT_FILTERS, query: "a&b=c,d" });
  assert.ok(!hash.slice(2).includes("&"));
  assert.equal(decode(hash).query, "a&b=c,d");
});

test("a leading hash is tolerated", () => {
  assert.deepEqual(decode("#sev=high").severities, ["high"]);
});

test("unknown keys are ignored", () => {
  assert.deepEqual(decode("nonsense=1&sev=low"), { severities: ["low"] });
});

test("malformed input does not throw", () => {
  assert.doesNotThrow(() => decode("sev"));
  assert.doesNotThrow(() => decode("q=%E0%A4%A"));
  assert.doesNotThrow(() => decode(null));
  assert.deepEqual(decode(""), {});
});

test("apply merges over the defaults", () => {
  const filters = apply("#sev=critical&sort=path");
  assert.deepEqual(filters.severities, ["critical"]);
  assert.equal(filters.sort, "path");
  assert.deepEqual(filters.statuses, DEFAULT_FILTERS.statuses);
});

test("apply with an empty hash gives the defaults back", () => {
  assert.deepEqual(apply(""), { ...DEFAULT_FILTERS });
});

test("a shareable view survives a full round trip", () => {
  const original = {
    ...DEFAULT_FILTERS,
    severities: ["critical"],
    sources: ["claude"],
    path: "app/billing/",
    sort: "severity",
    query: "authz",
  };
  assert.deepEqual(apply("#" + encode(original)), original);
});
