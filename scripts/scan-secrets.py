#!/usr/bin/env python3
"""Pattern scan only; print locations and rules, never matching values."""

import json
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
paths = subprocess.check_output(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root
).split(b"\0")
rules = {
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(rb"gh[opusr]_[A-Za-z0-9]{30,}"),
    "github_fine_grained": re.compile(rb"github_pat_[A-Za-z0-9_]{40,}"),
    "openai_key": re.compile(rb"sk-(?:proj-)?[A-Za-z0-9_-]{40,}"),
    "bearer_literal": re.compile(rb"Bearer [A-Za-z0-9_.-]{40,}"),
}
findings = []
scanned = 0
for raw in sorted(set(paths)):
    if not raw:
        continue
    relative = raw.decode()
    path = root / relative
    if not path.is_file() or path.is_symlink():
        continue
    scanned += 1
    data = path.read_bytes()
    for name, pattern in rules.items():
        for match in pattern.finditer(data):
            findings.append(
                {"path": relative, "line": data[: match.start()].count(b"\n") + 1, "rule": name}
            )
print(
    json.dumps(
        {"files_scanned": scanned, "findings": findings, "method": "patterns_only"}, indent=2
    )
)
raise SystemExit(bool(findings))
