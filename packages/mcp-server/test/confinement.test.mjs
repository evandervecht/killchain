// Regression tests for the MCP tool fixes from the self-audit: drives the built server
// over stdio like a client would. Run after `npm run build`.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const SERVER = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const root = mkdtempSync(join(tmpdir(), "kc-root-"));
const outside = mkdtempSync(join(tmpdir(), "kc-outside-"));
writeFileSync(join(root, "v.php"), '<?php\n$x = unserialize($_GET["a"]);\n');
writeFileSync(join(outside, "secret.php"), '<?php\n$x = unserialize($_GET["a"]);\n');

const env = { ...process.env };
delete env.KILLCHAIN_ROOT;
delete env.KILLCHAIN_ALLOW_INTERNAL;
const server = spawn(process.execPath, [SERVER], { cwd: root, env, stdio: ["pipe", "pipe", "inherit"] });
after(() => server.kill());

const waiting = new Map();
let buffer = "";
server.stdout.on("data", (chunk) => {
  buffer += chunk;
  let nl;
  while ((nl = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, nl).trim();
    buffer = buffer.slice(nl + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    waiting.get(msg.id)?.(msg);
  }
});

let nextId = 1;
function request(method, params) {
  const id = nextId++;
  server.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`no reply to ${method}`)), 15_000);
    waiting.set(id, (msg) => {
      clearTimeout(timer);
      resolve(msg);
    });
  });
}

const ready = request("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "test", version: "0" },
}).then(() => server.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n"));

async function call(name, args) {
  await ready;
  const reply = await request("tools/call", { name, arguments: args });
  return reply.result.content[0].text;
}

test("control: a file inside the root is scanned", async () => {
  const text = await call("check_file", { filePath: join(root, "v.php") });
  assert.ok(!text.startsWith("Refused"), text);
});

test("KC-M2: check_file refuses a file outside the root", async () => {
  assert.match(await call("check_file", { filePath: join(outside, "secret.php") }), /^Refused/);
  assert.match(await call("check_file", { filePath: join(root, "..", "nope.php") }), /^Refused/);
});

test("KC-M2: security_scan refuses a project outside the root", async () => {
  assert.match(await call("security_scan", { projectPath: outside }), /^Refused/);
});

test("KC-M1: the live scanner refuses local, internal and non-http targets", async () => {
  for (const url of [
    "http://127.0.0.1:1/",
    "http://169.254.169.254/latest/meta-data/",
    "https://10.0.0.5/",
    "192.168.1.1",
    "http://[::1]/",
    "file:///etc/passwd",
  ]) {
    assert.match(await call("security_scan_live", { url }), /^Refused/, url);
  }
});

test("KC-D6: the sandbox tool refuses option-like package specs", async () => {
  for (const pkg of ["--registry=http://x.example/", "a/../b"]) {
    assert.match(await call("dependency_sandbox", { ecosystem: "npm", package: pkg }), /Invalid package name/, pkg);
  }
});
