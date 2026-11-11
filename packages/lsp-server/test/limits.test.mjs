// Regression test for KC-M5 in the LSP server: an oversized line must not stall it.
// Drives the built server over stdio. Run after `npm run build`.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const SERVER = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const server = spawn(process.execPath, [SERVER, "--stdio"], { stdio: ["pipe", "pipe", "inherit"] });
after(() => server.kill());

const send = (msg) => {
  const body = JSON.stringify({ jsonrpc: "2.0", ...msg });
  server.stdin.write(`Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
};

const handlers = [];
let buffer = Buffer.alloc(0);
server.stdout.on("data", (chunk) => {
  buffer = Buffer.concat([buffer, chunk]);
  for (;;) {
    const headerEnd = buffer.indexOf("\r\n\r\n");
    if (headerEnd < 0) return;
    const length = Number(/Content-Length: (\d+)/i.exec(buffer.subarray(0, headerEnd).toString())[1]);
    if (buffer.length < headerEnd + 4 + length) return;
    const msg = JSON.parse(buffer.subarray(headerEnd + 4, headerEnd + 4 + length).toString());
    buffer = buffer.subarray(headerEnd + 4 + length);
    handlers.forEach((h) => h(msg));
  }
});

const next = (match, ms = 15_000) =>
  new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timed out waiting for the server")), ms);
    handlers.push((msg) => {
      if (match(msg)) {
        clearTimeout(timer);
        resolve(msg);
      }
    });
  });

test("KC-M5: an oversized line is skipped and the rest of the file still gets diagnostics", async () => {
  send({ id: 1, method: "initialize", params: { processId: null, rootUri: null, capabilities: {} } });
  await next((m) => m.id === 1);
  send({ method: "initialized", params: {} });

  const uri = "file:///tmp/kc-test.php";
  const text = '<?php\n$x = unserialize($_GET["a"]);\n' + "$_POST[".repeat(60_000) + "\n";
  const start = Date.now();
  send({ method: "textDocument/didOpen", params: { textDocument: { uri, languageId: "php", version: 1, text } } });
  const published = await next((m) => m.method === "textDocument/publishDiagnostics" && m.params.uri === uri);

  assert.ok(Date.now() - start < 10_000, "diagnostics took too long");
  const lines = published.params.diagnostics.map((d) => d.range.start.line);
  assert.ok(lines.length > 0, "the normal line got no diagnostics");
  assert.ok(!lines.includes(2), "the oversized line was scanned");
});
