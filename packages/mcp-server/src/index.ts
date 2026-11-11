#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { resolve, dirname, relative, isAbsolute } from "node:path";
import { realpathSync } from "node:fs";
import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import { fileURLToPath } from "node:url";
import {
  scanProject,
  scanFile,
  scanLive,
  explainFinding,
  listReferences,
  getReference,
  lookupCvesForCheckpoint,
} from "@killchain/core";

const __dirname = dirname(fileURLToPath(import.meta.url));
// Skill root is two levels up from packages/mcp-server/dist/
const SKILL_ROOT = resolve(__dirname, "../../..");

const server = new McpServer({
  name: "killchain",
  version: "0.1.0",
});

// Tool arguments come from a model that the scanned repository may have prompt-injected,
// so file tools stay inside one root and the live scanner stays off internal addresses.
const ALLOWED_ROOT = realpathSync(process.env.KILLCHAIN_ROOT ?? process.cwd());

function insideRoot(p: string): string | null {
  try {
    const real = realpathSync(resolve(p));
    const rel = relative(ALLOWED_ROOT, real);
    return rel.startsWith("..") || isAbsolute(rel) ? null : real;
  } catch {
    return null;
  }
}

const refuse = (text: string) => ({ content: [{ type: "text" as const, text }] });
const OUTSIDE_ROOT = `Refused: the path is outside ${ALLOWED_ROOT}. Start the server in the project directory or set KILLCHAIN_ROOT.`;

const internalNets = new BlockList();
for (const [net, bits] of [
  ["127.0.0.0", 8], ["10.0.0.0", 8], ["172.16.0.0", 12], ["192.168.0.0", 16],
  ["169.254.0.0", 16], ["100.64.0.0", 10], ["0.0.0.0", 8],
] as const) internalNets.addSubnet(net, bits);
internalNets.addSubnet("::1", 128, "ipv6");
internalNets.addSubnet("fc00::", 7, "ipv6");
internalNets.addSubnet("fe80::", 10, "ipv6");

// shortcut: checks the addresses the name resolves to now; a DNS answer that changes
// before the request (rebinding) is not covered. Pin the resolved address if that matters.
async function isInternalUrl(url: string): Promise<boolean> {
  try {
    const host = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`).hostname.replace(/^\[|\]$/g, "");
    const family = isIP(host);
    const addrs = family ? [{ address: host, family }] : await lookup(host, { all: true });
    return addrs.some((a) => internalNets.check(a.address, a.family === 6 ? "ipv6" : "ipv4"));
  } catch {
    return true;
  }
}

// === Tools ===

server.tool(
  "security_scan",
  "Scan a project directory for security vulnerabilities. Auto-detects languages and frameworks, runs relevant checkpoints, returns structured findings.",
  {
    projectPath: z.string().describe("Absolute path to the project directory to scan"),
  },
  async ({ projectPath }) => {
    const root = insideRoot(projectPath);
    if (!root) return refuse(OUTSIDE_ROOT);
    const result = await scanProject(root, SKILL_ROOT);
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  },
);

server.tool(
  "check_file",
  "Scan a single file for security vulnerabilities. Runs all checkpoints matching the file's language/extension.",
  {
    filePath: z.string().describe("Absolute path to the file to check"),
  },
  async ({ filePath }) => {
    const file = insideRoot(filePath);
    if (!file) return refuse(OUTSIDE_ROOT);
    const findings = await scanFile(file, SKILL_ROOT);
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              file: filePath,
              findings,
              count: findings.length,
            },
            null,
            2,
          ),
        },
      ],
    };
  },
);

server.tool(
  "explain_finding",
  "Get detailed reference documentation for a checkpoint ID, including vulnerable/secure code examples and remediation guidance.",
  {
    checkpointId: z
      .string()
      .describe("The checkpoint ID (e.g., SA-PY-01, SA-JS-06, SA-REACT-01)"),
  },
  async ({ checkpointId }) => {
    const result = explainFinding(SKILL_ROOT, checkpointId);
    if (!result || !result.reference) {
      return {
        content: [
          {
            type: "text" as const,
            text: `No reference documentation found for checkpoint ${checkpointId}`,
          },
        ],
      };
    }
    return {
      content: [
        {
          type: "text" as const,
          text: result.reference,
        },
      ],
    };
  },
);

server.tool(
  "security_scan_live",
  "Scan a live URL for security misconfigurations — checks security headers (HSTS, CSP), TLS version, CORS policy, cookie flags, open redirects, and verbose error pages.",
  {
    url: z.string().describe("URL to scan (e.g., https://example.com)"),
  },
  async ({ url }) => {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(url) && !/^https?:\/\//i.test(url)) {
      return refuse("Refused: only http and https URLs can be scanned.");
    }
    if (process.env.KILLCHAIN_ALLOW_INTERNAL !== "1" && (await isInternalUrl(url))) {
      return refuse("Refused: the URL points at a local or internal address. Set KILLCHAIN_ALLOW_INTERNAL=1 to allow that.");
    }
    const result = await scanLive(url);
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  },
);

server.tool(
  "lookup_cves",
  "Look up known CVEs associated with a checkpoint ID by querying the NVD API. Returns matching CVEs with CVSS scores and descriptions.",
  {
    checkpointId: z
      .string()
      .describe("The checkpoint ID to look up CVEs for (e.g., SA-PY-01, SA-JAVA-03)"),
  },
  async ({ checkpointId }) => {
    const cves = await lookupCvesForCheckpoint(checkpointId);
    return {
      content: [
        {
          type: "text" as const,
          text:
            cves.length > 0
              ? JSON.stringify(cves, null, 2)
              : `No CVEs found for checkpoint ${checkpointId} (may not have a CWE mapping or NVD returned no results)`,
        },
      ],
    };
  },
);

server.tool(
  "dependency_sandbox",
  "Install a package in an isolated Docker container and monitor for suspicious behavior (network calls to non-registry hosts, unexpected file writes, process spawning). Requires Docker.",
  {
    ecosystem: z.enum(["npm", "pip", "go", "rust", "dotnet"]).describe("Package ecosystem"),
    package: z.string().describe("Package name with optional version (e.g., lodash@4.17.21, requests==2.31.0, github.com/gin-gonic/gin, serde, Newtonsoft.Json)"),
  },
  async ({ ecosystem, package: pkg }) => {
    const { execFileSync } = await import("node:child_process");
    const scriptPath = resolve(SKILL_ROOT, "scripts/dependency-sandbox.sh");

    // Validate package name — strict allowlist (no shell metacharacters)
    if (!/^[a-zA-Z0-9@][a-zA-Z0-9@._\-/=:^~]*$/.test(pkg) || pkg.includes("..")) {
      return {
        content: [{ type: "text" as const, text: `Invalid package name: contains disallowed characters` }],
      };
    }

    try {
      // Use execFileSync with argument array to prevent shell injection
      const output = execFileSync("bash", [scriptPath, ecosystem, pkg], {
        timeout: 120000,
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "pipe"],
      });
      return {
        content: [{ type: "text" as const, text: output }],
      };
    } catch (e: any) {
      return {
        content: [
          {
            type: "text" as const,
            text: e.stdout || e.stderr || `Sandbox failed: ${e.message}`,
          },
        ],
      };
    }
  },
);

// === Resources ===

server.resource(
  "references",
  "security-audit://references",
  async (uri) => {
    const refs = listReferences(SKILL_ROOT);
    return {
      contents: [
        {
          uri: uri.href,
          mimeType: "application/json",
          text: JSON.stringify(refs, null, 2),
        },
      ],
    };
  },
);

// === Prompts ===

server.prompt(
  "security_audit",
  "Run a comprehensive security audit on a project",
  {
    projectPath: z
      .string()
      .describe("Absolute path to the project directory"),
  },
  ({ projectPath }) => ({
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Run a comprehensive security audit on the project at ${projectPath}.

1. First, use the security_scan tool to detect languages and run all relevant checkpoints.
2. Review the findings, prioritizing critical and high severity issues.
3. For each high-severity finding, use explain_finding to get the reference documentation.
4. Provide a summary report with:
   - Detected stack (languages/frameworks)
   - Total findings by severity
   - Top 5 most critical findings with remediation steps
   - Overall security posture assessment`,
        },
      },
    ],
  }),
);

server.prompt(
  "quick_check",
  "Quick security check on a single file",
  {
    filePath: z.string().describe("Absolute path to the file to check"),
  },
  ({ filePath }) => ({
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Quick security check on ${filePath}. Use check_file to scan it, then explain any findings using explain_finding.`,
        },
      },
    ],
  }),
);

// === Start ===

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
