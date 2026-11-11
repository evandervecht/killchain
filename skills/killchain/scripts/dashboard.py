#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Turn an audit's findings.json into one self-contained dashboard.html.

Usage: dashboard.py findings.json [dashboard.html]

The file format is described in references/finding-verification.md.
Finding text comes from the audited code, so it is untrusted: it is embedded
as escaped JSON and rendered with textContent only, never as HTML.
"""
import json
import sys
from pathlib import Path

VERDICTS = ("confirmed", "unproven", "hardening", "refuted")
SEVERITIES = ("critical", "high", "medium", "low")


def validate(data) -> list[str]:
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        return ["top level must be an object with a 'findings' list"]
    errs = []
    verdicts = {}
    for i, f in enumerate(data["findings"]):
        if not isinstance(f, dict):
            errs.append(f"findings[{i}]: must be an object")
            continue
        fid = f.get("id") or f"findings[{i}]"
        for key in ("id", "class", "location", "verdict"):
            if not isinstance(f.get(key), str) or not f[key]:
                errs.append(f"{fid}: missing '{key}'")
        if f.get("verdict") not in VERDICTS:
            errs.append(f"{fid}: verdict must be one of {', '.join(VERDICTS)}")
        if f.get("verdict") == "confirmed" and f.get("severity") not in SEVERITIES:
            errs.append(f"{fid}: confirmed needs severity ({', '.join(SEVERITIES)})")
        if fid in verdicts:
            errs.append(f"{fid}: duplicate id")
        verdicts[fid] = f.get("verdict")

    chains = data.get("chains", [])
    if not isinstance(chains, list):
        return errs + ["'chains' must be a list"]
    for i, c in enumerate(chains):
        if not isinstance(c, dict):
            errs.append(f"chains[{i}]: must be an object")
            continue
        cid = c.get("id") or f"chains[{i}]"
        for key in ("id", "title", "impact"):
            if not isinstance(c.get(key), str) or not c[key]:
                errs.append(f"{cid}: missing '{key}'")
        if c.get("severity") not in SEVERITIES:
            errs.append(f"{cid}: severity must be one of {', '.join(SEVERITIES)}")
        steps = c.get("steps")
        if not isinstance(steps, list) or len(steps) < 2:
            errs.append(f"{cid}: a chain needs at least two steps")
            continue
        for s in steps:
            if s not in verdicts:
                errs.append(f"{cid}: step '{s}' is not a finding id")
            elif verdicts[s] == "refuted":
                errs.append(f"{cid}: step '{s}' is refuted and cannot be part of a chain")
    return errs


def render(data) -> str:
    # Escape <, > and & so nothing in the data can end the script element.
    blob = json.dumps(data).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return PAGE.replace("__DATA__", blob)


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    src = Path(argv[1])
    out = Path(argv[2]) if len(argv) == 3 else src.with_name("dashboard.html")
    try:
        data = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"{src}: {e}", file=sys.stderr)
        return 1
    errs = validate(data)
    if errs:
        print("\n".join(errs), file=sys.stderr)
        return 1
    out.write_text(render(data), encoding="utf-8")
    print(out)
    return 0


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Security audit</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#1a1f2b;--mute:#5d6678;--line:#dfe3ea;--critical:#b3261e;--high:#b9500a;--medium:#7d6300;--low:#2c6e49;--accent:#3b5bdb}
@media(prefers-color-scheme:dark){:root{--bg:#12151c;--card:#1b202b;--ink:#e8ebf1;--mute:#9aa4b8;--line:#2c3443;--critical:#ff8a80;--high:#ffb074;--medium:#e6c74c;--low:#7fd1a0;--accent:#91a7ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:24px;margin:0}
h2{font-size:18px;margin:36px 0 12px}
.meta,.mute{color:var(--mute)}
code{font:13px ui-monospace,Consolas,monospace;overflow-wrap:anywhere}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-top:20px}
.tile,.chain,details{background:var(--card);border:1px solid var(--line);border-radius:10px}
.tile{padding:14px 16px}
.tile b{display:block;font-size:28px;line-height:1.1}
.sev{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.badge{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:0 8px;font-size:12px;font-weight:600;white-space:nowrap;color:var(--mute)}
.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}
.confirmed{color:var(--critical)}.unproven,.potential{color:var(--medium)}.hardening{color:var(--accent)}
.chain{padding:16px;margin-bottom:12px}
.chain header{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.steps{display:flex;flex-wrap:wrap;gap:8px;align-items:stretch}
.step{flex:1 1 170px;max-width:260px;border:1px solid var(--line);border-radius:8px;padding:10px;color:inherit;text-decoration:none;display:flex;flex-direction:column;gap:4px}
a.step:hover{border-color:var(--accent)}
.goal{border-color:currentColor}
.arrow{align-self:center;color:var(--mute);font-size:20px}
small{color:var(--mute);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.controls{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
button,input{font:inherit;color:inherit;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:6px 12px}
button{cursor:pointer}
button[aria-pressed=true]{border-color:var(--accent);color:var(--accent)}
input{flex:1 1 200px}
details{margin-bottom:8px}
summary{cursor:pointer;padding:10px 14px;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.body{padding:4px 14px 14px;border-top:1px solid var(--line)}
dt{color:var(--mute);font-size:12px;text-transform:uppercase;letter-spacing:.04em;margin-top:12px}
dd{margin:2px 0 0}
ol{margin:0;padding-left:20px}
</style>
</head>
<body>
<main id="app"></main>
<script id="data" type="application/json">__DATA__</script>
<script>
const D = JSON.parse(document.getElementById('data').textContent);
const F = D.findings, C = D.chains || [];
const VERDICTS = ['confirmed', 'unproven', 'hardening', 'refuted'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const byId = Object.fromEntries(F.map(f => [f.id, f]));
const inChain = {};
C.forEach(c => c.steps.forEach(s => (inChain[s] = inChain[s] || []).push(c.id)));
const list = v => [].concat(v || []);

// Builds elements from text nodes only; finding text is never parsed as HTML.
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const k in attrs || {}) {
    if (k.startsWith('on')) e.addEventListener(k.slice(2), attrs[k]);
    else e.setAttribute(k, attrs[k]);
  }
  e.append(...kids.flat().filter(k => k != null && k !== false));
  return e;
}
const badge = (text, cls) => h('span', {class: 'badge ' + (cls || text)}, text);
const count = (arr, key, val) => arr.filter(x => x[key] === val).length;
const rank = f => VERDICTS.indexOf(f.verdict) * 10 + (SEVERITIES.indexOf(f.severity) + 5) % 5;

const app = document.getElementById('app');
document.title = 'Security audit: ' + (D.target || 'report');
app.append(
  h('h1', null, document.title),
  h('p', {class: 'meta'}, [D.date, D.commit && 'commit ' + D.commit].filter(Boolean).join(' · ')),
  h('div', {class: 'tiles'},
    VERDICTS.map(v => h('div', {class: 'tile'}, h('b', null, String(count(F, 'verdict', v))), v)),
    h('div', {class: 'tile'}, h('b', null, String(C.length)), 'attack chains')),
  h('div', {class: 'sev'}, h('span', {class: 'mute'}, 'Confirmed by severity:'),
    SEVERITIES.map(s => badge(count(F.filter(f => f.verdict === 'confirmed'), 'severity', s) + ' ' + s, s)))
);

function show(id) {
  const el = document.getElementById('f-' + id);
  if (el) { el.hidden = false; el.open = true; }
}

if (C.length) {
  app.append(h('h2', null, 'Attack chains'));
  for (const c of C) {
    const status = c.steps.every(s => byId[s].verdict === 'confirmed') ? 'confirmed' : 'potential';
    const steps = [];
    c.steps.forEach((s, i) => {
      const f = byId[s];
      steps.push(
        h('a', {class: 'step', href: '#f-' + s, onclick: () => show(s)},
          h('small', null, 'Step ' + (i + 1)), h('strong', null, f.class),
          h('code', null, f.location), h('span', null, badge(f.verdict))),
        h('span', {class: 'arrow', 'aria-hidden': 'true'}, '→'));
    });
    steps.push(h('div', {class: 'step goal ' + c.severity}, h('small', null, 'Result'), c.impact));
    app.append(h('section', {class: 'chain'},
      h('header', null, h('code', null, c.id), h('strong', null, c.title),
        badge(c.severity), badge(status === 'confirmed' ? 'all steps confirmed' : 'potential', status)),
      h('div', {class: 'steps'}, steps)));
  }
}

app.append(h('h2', null, 'Findings'));
let verdict = '', query = '';
const rows = [];
function apply() {
  for (const r of rows) r.el.hidden = (verdict && r.f.verdict !== verdict) || (query && !r.text.includes(query));
  for (const b of buttons) b.setAttribute('aria-pressed', String(b.dataset.v === verdict));
}
const buttons = ['', ...VERDICTS].map(v => h('button', {
  'data-v': v, onclick: () => { verdict = v; apply(); }
}, v ? v + ' (' + count(F, 'verdict', v) + ')' : 'all (' + F.length + ')'));
app.append(h('div', {class: 'controls'}, buttons,
  h('input', {type: 'search', placeholder: 'Filter by text', 'aria-label': 'Filter findings by text',
    oninput: e => { query = e.target.value.toLowerCase(); apply(); }})));

const field = (label, value) => value && [h('dt', null, label), h('dd', null, value)];
for (const f of [...F].sort((a, b) => rank(a) - rank(b))) {
  const el = h('details', {id: 'f-' + f.id},
    h('summary', null,
      f.severity && badge(f.severity), h('code', null, f.id), h('strong', null, f.class),
      h('code', {class: 'mute'}, f.location), badge(f.verdict),
      list(inChain[f.id]).map(c => badge('chain ' + c, 'hardening'))),
    h('dl', {class: 'body'},
      field('Impact', f.impact),
      field('Preconditions', f.preconditions),
      list(f.trace).length && field('Trace', h('ol', null, list(f.trace).map(t => h('li', null, h('code', null, t))))),
      field('Fix', f.fix),
      field('Defeated by', f.defeated_by),
      field('Open fact', f.open_fact),
      field('CWE', f.cwe),
      field('CVSS', f.cvss && h('code', null, f.cvss)),
      field('Checkpoint', f.checkpoint)));
  rows.push({el, f, text: JSON.stringify(f).toLowerCase()});
  app.append(el);
}
if (!F.length) app.append(h('p', {class: 'mute'}, 'No findings recorded.'));
apply();
if (location.hash.startsWith('#f-')) show(decodeURIComponent(location.hash.slice(3)));
</script>
</body>
</html>
"""

if __name__ == "__main__":
    sys.exit(main(sys.argv))
