---
name: security-audit
description: "Use for security audits and any code security review: finding vulnerabilities (OWASP Top 10, CWE Top 25, XSS/SQLi/SSRF/XXE/CSRF), CVSS v4.0 scoring, leaked secrets, dependency CVEs, IaC (Dockerfile/Terraform), Kubernetes and GitHub Actions, API and GraphQL, frontend, cloud and mobile, and AI agent/LLM security (OWASP LLM Top 10). Runs parallel hunter and verifier subagents, links findings into attack chains and builds an HTML findings dashboard. Covers 15 languages and 26 frameworks."
license: "MIT. See LICENSE-MIT"
compatibility: "Requires grep, jq, gh CLI. Python 3.10+ for the dashboard."
metadata:
  author: E van der Vecht
  version: "3.4.0"
  repository: https://github.com/evandervecht/killchain
allowed-tools: Bash(grep:*) Bash(jq:*) Bash(gh:*) Bash(python3:*) Read Glob Grep
---

# Security Audit Skill

Security audits for any project: OWASP Top 10, CWE Top 25 2025 and CVSS v4.0, with 565+ checkpoints and 85 reference guides across 15 languages, 26 frameworks, IaC, Kubernetes, GitHub Actions, APIs, frontend and AI/LLM agents. Load references on demand; never load them all.

## Audit Workflow

Scanner hits, checkpoint matches and review notes are candidates, not findings. Report a vulnerability only after an independent verifier has tried and failed to disprove it.

**Mode.** A security question, or a review of one file or one finding, is guidance: answer from the matching references and write no files. A request to audit a project is a full audit: run every step below.

1. **Detect.** Identify the stack with `stack-detection.md` and load only the matching references plus `owasp-top10.md` and `cwe-top25.md`. Run the dispatcher and the checkpoints for the detected stack. Note the entry points and who may call them.
2. **Hunt.** Split the project into areas (one per service or stack, plus access control, secrets and dependencies, and IaC/CI where present). With subagents, start one hunter per area in parallel; without them, review the areas one by one. Hunters return candidates only.
3. **Triage.** Drop fixture, test, vendored and generated paths; merge duplicates; report pure hygiene issues as `hardening`.
4. **Verify.** Hand each remaining candidate to a fresh subagent, in parallel (or a separate pass after hunting), with only the claim, never the hunter's reasoning. The verifier follows the refutation checklist and returns `confirmed`, `unproven`, `refuted` or `hardening`.
5. **Score.** CVSS v4.0 (`cvss-scoring.md`) and a severity for `confirmed` only.
6. **Chain.** Link verified findings into attack chains where one finding's impact gives the attacker what the next one requires.
7. **Report.** Chains first, then confirmed with source-to-sink trace and impact, then unproven with the one open fact, then hardening, then a short refuted list. Close with `audit-checklist.md`.
8. **Dashboard.** Write the records and chains to `findings.json` and run `scripts/dashboard.py` to produce `dashboard.html`. Tell the user where it is.

Severity needs a concrete impact. A missing second layer, where another layer already blocks the attack, is `hardening`. Full protocol, hunter and verifier prompts, chain rules and the `findings.json` format: `finding-verification.md`.

## Reference Files

All files are in `references/`. Language, framework, cloud, CMS and mobile references are mapped in `stack-detection.md`.

- **Core**: `owasp-top10.md`, `cwe-top25.md`, `cvss-scoring.md`, `audit-checklist.md`
- **Verification**: `finding-verification.md` (multi-agent run, verdicts, refutation checklist, prompts, attack chains, `findings.json` and dashboard)
- **Vulnerability Prevention**: `xxe-prevention.md`, `deserialization-prevention.md`, `path-traversal-prevention.md`, `file-upload-security.md`, `input-validation.md`, `api-key-encryption.md`
- **Secure Architecture**: `authentication-patterns.md`, `security-headers.md`, `security-logging.md`, `cryptography-guide.md`
- **Modern Threats**: `modern-attacks.md`, `cve-patterns.md`, `cve-database.md`
- **DevSecOps**: `ci-security-pipeline.md`, `supply-chain-security.md`, `automated-scanning.md` (semgrep, trivy, gitleaks)
- **Incident Response**: `supply-chain-incident-response.md` (GitHub Actions supply chain compromises)
- **Infrastructure**: `iac-security.md` (Dockerfile, Compose, Terraform), `kubernetes-security.md`, `github-actions-security.md`
- **API and Frontend**: `api-security.md` (OWASP API Top 10), `graphql-security.md`, `frontend-security.md` (DOM XSS, SRI, CORS, postMessage, storage)
- **AI/LLM Security**: `llm-security.md` (OWASP LLM Top 10 2025, agent/skill/MCP auditing), `agent-skill-scan.md` (vetting one installed agent skill: what to check, verdict format)
- **Compliance**: `compliance-gdpr.md`, `compliance-hipaa.md`, `compliance-iso27001.md`, `compliance-nist-csf.md`, `compliance-pci-dss.md`, `compliance-soc2.md`, `compliance-eu-ai-act.md`

## Scripts

```bash
# Multi-language security audit (auto-detects stack)
./scripts/security-audit-dispatcher.sh /path/to/project

# PHP-only project security audit (legacy)
./skills/security-audit/scripts/security-audit.sh /path/to/project

# GitHub repository security audit
./skills/security-audit/scripts/github-security-audit.sh owner/repo

# Agent skill scan, pattern pass (then review per references/agent-skill-scan.md)
./skills/security-audit/scripts/skill-scan.sh ~/.claude/skills/<skill>

# Findings dashboard (one self-contained HTML file, no network access)
python3 ./skills/security-audit/scripts/dashboard.py findings.json
```

---

> **Contributing:** https://github.com/evandervecht/killchain
