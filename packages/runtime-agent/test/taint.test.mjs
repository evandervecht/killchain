// Regression test for KC-E4: the taint map must stay bounded. Run after `npm run build`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { markTainted, isTainted } from "../dist/taint-tracker.js";

const source = { type: "query", key: "k" };

test("KC-E4: the taint map evicts the oldest entries past its cap", () => {
  for (let i = 0; i < 10_050; i++) markTainted(`value-${i}`, source);
  assert.equal(isTainted("value-0"), null, "oldest entry was not evicted");
  assert.ok(isTainted("value-10049"), "newest entry is missing");
});

test("KC-E4: short values are not tainted, so they cannot block ordinary calls", () => {
  markTainted("ab", source);
  assert.equal(isTainted("ab"), null);
  markTainted("abcd", source);
  assert.ok(isTainted("abcd"));
});
