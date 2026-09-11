"""Experimental deployment eligibility; CLI presence is not network certification."""

import hashlib
import re
import shutil
import subprocess

REQUIRED_FLAGS = frozenset(
    {
        "--socket",
        "--sidecar-socket",
        "--bundle",
        "--credential-issuer",
        "--credential-audience",
        "--egress-allow",
    }
)


def inspect_sam_box_help(text):
    flags = set(re.findall(r"^\s+(--[a-z][a-z-]+)(?=\s|$)", text, re.MULTILINE))
    missing = sorted(REQUIRED_FLAGS - flags)
    return {
        "supported": False,
        "posture": "experimental",
        "missing_flags": missing,
        "help_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "blockers": (["required_flags_missing"] if missing else [])
        + [
            "network_matrix_unverified",
            "tun2socks_contract_unverified",
            "credential_lifecycle_unverified",
            "ui_gateway_bypass_unverified",
        ],
        "warnings": ["CLI flags alone do not prove named egress or credential enforcement."],
    }


def unavailable_report():
    return {
        "status": "unsupported",
        "supported": False,
        "posture": "experimental",
        "blockers": ["runtime_capability_probe_required", "network_matrix_unverified"],
        "network_enforcement_claimed": False,
    }


def probe_local():
    executable = shutil.which("sam-box")
    if not executable:
        return dict(unavailable_report(), missing_binaries=["sam-box"])
    try:
        value = subprocess.run(
            [executable, "run", "--help"], capture_output=True, text=True, timeout=5, check=False
        )
        if value.returncode != 0 or len(value.stdout) > 131072:
            return dict(unavailable_report(), blockers=["sam_box_help_unavailable"])
        return inspect_sam_box_help(value.stdout)
    except (OSError, subprocess.TimeoutExpired):
        return dict(unavailable_report(), blockers=["sam_box_probe_failed"])
