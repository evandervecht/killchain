#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Regression tests for the shell, sandbox and Python fixes from the self-audit.

Each test names the finding it guards (see docs/dependency-sandbox.md and the
commit that introduced the fix). The TypeScript fixes are tested per package
with `npm test`.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNERS = ROOT / "scripts/scanners"
BASH = shutil.which("bash")

KEY = "AKIA3F7XQ2MN8PLZK9WD"  # shaped like an AWS key, not a real one
CONNECT = '1234 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0\n'


def bash(script: Path, *args, env=None):
    return subprocess.run([BASH, str(script), *args], capture_output=True, text=True,
                          env={**os.environ, **(env or {})})


def symlink(link: Path, target: Path) -> bool:
    """Create a symlink the scripts' bash will also see as one; False where that is not possible."""
    if os.name == "nt":  # Git Bash and native Windows symlinks do not agree reliably
        return False
    link.symlink_to(target, target_is_directory=target.is_dir())
    return True


def test_secret_with_placeholder_word_is_reported(tmp):  # KC-S6
    (tmp / "src").mkdir()
    (tmp / "src/a.py").write_text(f'aws_key = "{KEY}"  # EXAMPLE dist build\n')
    out = bash(SCANNERS / "secrets.sh", str(tmp)).stdout
    assert "a.py" in out, out


def test_documentation_key_is_not_reported(tmp):  # KC-S6, the allowlist still works
    (tmp / "src").mkdir()
    (tmp / "src/doc.py").write_text('k = "AKIAIOSFODNN7EXAMPLE"\n')
    out = bash(SCANNERS / "secrets.sh", str(tmp)).stdout
    assert "doc.py" not in out, out


def test_excluded_directory_is_skipped_by_path(tmp):  # KC-S6, exclusions are path based
    (tmp / "dist").mkdir()
    (tmp / "dist/bundle.js").write_text(f'const k = "{KEY}";\n')
    out = bash(SCANNERS / "secrets.sh", str(tmp)).stdout
    assert "bundle.js" not in out, out


def test_scanners_cap_exit_status(tmp):  # KC-S8
    bare = [f.name for f in SCANNERS.glob("*.sh")
            if re.search(r'^exit "?\$ERRORS"?\s*$', f.read_text(encoding="utf-8"), re.M)]
    assert not bare, f"uncapped exit status in {bare}"
    r = subprocess.run([BASH, "-c", "ERRORS=256; exit $(( ERRORS > 255 ? 255 : ERRORS ))"])
    assert r.returncode == 255


def test_audits_ignore_project_config(tmp):  # KC-S5
    text = "".join(f.read_text(encoding="utf-8") for f in SCANNERS.glob("*.sh"))
    text += (ROOT / "skills/killchain/scripts/security-audit.sh").read_text(encoding="utf-8")
    for line in re.findall(r".*&& npm audit .*", text):
        assert "--registry=https://registry.npmjs.org/" in line, line
    for line in re.findall(r".*&& composer audit.*", text):
        assert "--no-plugins --no-scripts" in line, line
    for line in re.findall(r".*&& .*govulncheck \./.*", text):
        assert "GOTOOLCHAIN=local" in line, line


def test_symlinked_source_dir_is_not_followed(tmp):  # KC-S4
    outside = tmp / "outside"
    outside.mkdir()
    (outside / "leak.js").write_text("eval(userInput);\ndocument.write(location.hash);\n")
    project = tmp / "project"
    project.mkdir()
    if not symlink(project / "src", outside):
        return "skipped: no symlinks here"
    out = bash(SCANNERS / "javascript.sh", str(project)).stdout
    assert "leak.js" not in out, out


def test_sandbox_rejects_option_like_specs(tmp):  # KC-D6
    for spec in ("--registry=http://x.example/", "-r/etc/passwd", "a/../b"):
        r = bash(ROOT / "scripts/dependency-sandbox.sh", "npm", spec)
        assert r.returncode == 2 and "Invalid package name" in r.stdout, (spec, r.stdout, r.stderr)


def test_sandbox_refuses_modes_that_never_installed(tmp):  # KC-D7
    fake = tmp / "bin"
    fake.mkdir()
    docker = fake / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n")
    docker.chmod(0o755)
    env = {"PATH": f"{fake}{os.pathsep}{os.environ['PATH']}"}
    for mode in ("go", "rust", "dotnet"):
        r = bash(ROOT / "scripts/dependency-sandbox.sh", mode, "some-package", env=env)
        assert r.returncode == 2 and "not supported" in r.stdout, (mode, r.stdout, r.stderr)
        assert "CLEAN" not in r.stdout


def test_analyzer_does_not_write_through_a_planted_symlink(tmp):  # KC-D2
    victim = tmp / "victim.txt"
    victim.write_text("KEEP")
    results = tmp / "results"
    results.mkdir()
    (results / "strace.log").write_text(CONNECT)
    if not symlink(results / "ips.txt", victim):
        return "skipped: no symlinks here"
    bash(ROOT / "scripts/sandbox/analyze-strace.sh", str(results / "strace.log"))
    assert victim.read_text() == "KEEP", "host file was overwritten through the symlink"
    assert not (results / "ips.txt").is_symlink()


def test_python_taint_map_is_bounded(tmp):  # KC-E4
    code = (
        "import sys; sys.path.insert(0, sys.argv[1])\n"
        "import security_audit_runtime as r\n"
        "for i in range(10_050): r.mark_tainted(f'value-{i}', 'query', 'k')\n"
        "assert len(r._tainted_values) <= 10_000, len(r._tainted_values)\n"
        "assert r.is_tainted('value-0') is None and r.is_tainted('value-10049')\n"
        "r.mark_tainted('ab', 'query', 'k'); assert r.is_tainted('ab') is None\n"
    )
    r = subprocess.run([sys.executable, "-c", code, str(ROOT / "packages/runtime-agent/python")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def main() -> int:
    if not BASH:
        print("bash not found")
        return 1
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    failed = 0
    for test in tests:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                note = test(Path(tmp).resolve())
                print(f"PASS {test.__name__}" + (f" ({note})" if note else ""))
            except AssertionError as e:
                failed += 1
                print(f"FAIL {test.__name__}: {str(e)[:600]}")
    print(f"\n{len(tests) - failed}/{len(tests)} self-audit regression tests passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
