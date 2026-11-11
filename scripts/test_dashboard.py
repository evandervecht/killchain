#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Test the findings dashboard generator (skills/security-audit/scripts/dashboard.py).

Run with a path argument to also keep the sample dashboard: test_dashboard.py out.html
"""

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "skills/security-audit/scripts/dashboard.py"

SAMPLE = {
    "target": "acme-shop",
    "date": "2026-11-11",
    "commit": "8560c26",
    "findings": [
        {
            "id": "SA-API-01-001", "checkpoint": "SA-API-01", "class": "Broken object-level authorization",
            "cwe": "CWE-639", "verdict": "confirmed", "severity": "high",
            "location": "app/api/orders.py:52",
            "trace": ["app/api/orders.py:44 order_id read from the URL",
                      "app/api/orders.py:52 Order.get(order_id) with no owner check"],
            "preconditions": "Any authenticated customer",
            "impact": "Reads any customer's order, including the support note field",
            "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "fix": "Filter the query by the session's customer id",
        },
        {
            "id": "SA-JS-06-001", "checkpoint": "SA-JS-06", "class": "Stored XSS",
            "cwe": "CWE-79", "verdict": "confirmed", "severity": "medium",
            "location": "web/admin/OrderNote.jsx:19",
            "trace": ["app/api/orders.py:71 note stored unescaped",
                      "web/admin/OrderNote.jsx:19 dangerouslySetInnerHTML={{__html: note}}"],
            "preconditions": "Write access to an order's support note",
            "impact": "Runs script in an admin's browser session",
            "fix": "Render the note as text",
        },
        {
            "id": "SA-PY-03-001", "checkpoint": "SA-PY-03", "class": "Command injection",
            "cwe": "CWE-78", "verdict": "unproven",
            "location": "app/tasks/export.py:88",
            "open_fact": "Whether EXPORT_FORMATS is restricted in the production config",
        },
        {
            "id": "SA-HDR-01-001", "class": "Missing Content-Security-Policy", "verdict": "hardening",
            "location": "app/middleware.py:12", "defeated_by": "Not a vulnerability on its own",
        },
        {
            # Hostile text from the audited code must never become markup.
            "id": "SA-PY-01-001", "class": "</script><script>alert(1)</script>", "verdict": "refuted",
            "location": "app/db.py:30", "defeated_by": "app/db.py:28 query is parameterised",
        },
    ],
    "chains": [
        {
            "id": "CH-1", "title": "Customer to admin session", "severity": "critical",
            "steps": ["SA-API-01-001", "SA-JS-06-001"],
            "impact": "Any customer takes over an admin session",
        },
        {
            "id": "CH-2", "title": "Admin session to worker shell", "severity": "critical",
            "steps": ["SA-JS-06-001", "SA-PY-03-001"],
            "impact": "Shell commands as the export worker, if the open fact holds",
        },
    ],
}


def run(data, out: Path):
    src = out.with_suffix(".json")
    src.write_text(json.dumps(data), encoding="utf-8")
    return subprocess.run([sys.executable, str(SCRIPT), str(src), str(out)], capture_output=True, text=True)


def broken(change):
    data = copy.deepcopy(SAMPLE)
    change(data)
    return data


BAD = [
    ("chain step that is not a finding", lambda d: d["chains"][0]["steps"].append("NOPE")),
    ("chain step that is refuted", lambda d: d["chains"][0]["steps"].append("SA-PY-01-001")),
    ("chain with one step", lambda d: d["chains"][0].update(steps=["SA-API-01-001"])),
    ("confirmed without severity", lambda d: d["findings"][0].pop("severity")),
    ("unknown verdict", lambda d: d["findings"][0].update(verdict="maybe")),
    ("duplicate id", lambda d: d["findings"].append(d["findings"][0])),
    ("no findings list", lambda d: d.pop("findings")),
]


def main() -> int:
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(tmp) / "dashboard.html"
        r = run(SAMPLE, Path(tmp) / "good.html")
        html = (Path(tmp) / "good.html").read_text(encoding="utf-8") if r.returncode == 0 else ""
        if r.returncode != 0:
            failures.append(f"valid sample rejected: {r.stderr}")
        elif "<script>alert(1)" in html or "SA-API-01-001" not in html:
            failures.append("sample output is missing data or contains unescaped markup")
        elif len(sys.argv) > 1:
            out.write_text(html, encoding="utf-8")
        for name, change in BAD:
            if run(broken(change), Path(tmp) / "bad.html").returncode == 0:
                failures.append(f"accepted: {name}")
    for f in failures:
        print(f"FAIL {f}")
    print(f"{1 + len(BAD) - len(failures)}/{1 + len(BAD)} dashboard tests passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
