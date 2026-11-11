// Regression tests for the scanner fixes from the self-audit. Run after `npm run build`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, symlinkSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { scanFile, scanProject, getReference } from "../dist/index.js";

const SKILL_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const VULNERABLE = '<?php\n$x = unserialize($_GET["a"]);\n';
const dir = mkdtempSync(join(tmpdir(), "kc-core-"));
const file = (name, content) => {
  const p = join(dir, name);
  writeFileSync(p, content);
  return p;
};

test("control: a vulnerable file produces findings", async () => {
  assert.ok((await scanFile(file("v.php", VULNERABLE), SKILL_ROOT)).length > 0);
});

test("KC-M5: an oversized line is skipped quickly and other lines are still scanned", async () => {
  const p = file("long.php", VULNERABLE + "$_POST[".repeat(60_000) + "\n");
  const start = Date.now();
  const findings = await scanFile(p, SKILL_ROOT);
  assert.ok(Date.now() - start < 5_000, "scan took too long");
  assert.ok(findings.length > 0, "the normal line was not scanned");
  assert.ok(findings.every((f) => f.line !== 3), "the oversized line was scanned");
});

test("KC-M4: a file over 1 MB is skipped", async () => {
  const p = file("huge.php", VULNERABLE + "// padding\n".repeat(100_000));
  assert.deepEqual(await scanFile(p, SKILL_ROOT), []);
});

test("KC-M4: a symlink is not followed", async (t) => {
  const target = file("target.php", VULNERABLE);
  const link = join(dir, "link.php");
  try {
    symlinkSync(target, link);
  } catch {
    return t.skip("cannot create symlinks here");
  }
  assert.deepEqual(await scanFile(link, SKILL_ROOT), []);

  const project = join(dir, "project");
  mkdirSync(project);
  symlinkSync(target, join(project, "evil.php"));
  const result = await scanProject(project, SKILL_ROOT);
  assert.deepEqual(result.findings.filter((f) => f.file.includes("evil.php")), []);
});

test("KC-M3: reference lookup rejects names with a path", () => {
  assert.equal(getReference(SKILL_ROOT, "../SKILL.md"), null);
  assert.equal(getReference(SKILL_ROOT, "..\\SKILL.md"), null);
  assert.ok(getReference(SKILL_ROOT, "owasp-top10.md"));
});
