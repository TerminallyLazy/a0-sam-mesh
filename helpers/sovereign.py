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
            "nano_init_contract_unverified",
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


# A report is a short-lived operator attestation emitted by the disposable runtime
# harness. It is never model/plugin config. A read-only public copy is mounted
# in the agent for guest_probe; it contains hashes and outcomes, never credentials.
REQUIRED_RUNTIME_CHECKS = frozenset(
    {
        "tun_real",
        "named_external_allowed",
        "unapproved_name_denied",
        "literal_ip_denied",
        "literal_ipv6_denied",
        "udp_denied",
        "dns_no_external_packets",
        "mesh_models_allowed",
        "mesh_mcp_allowed",
        "named_mesh_mcp_allowed",
        "mesh_admin_denied",
        "node_authority_absent",
        "ui_reachable",
        "ui_websocket",
        "ui_gateway_no_egress",
        "socket_separation",
        "missing_credential_denied",
        "expired_credential_denied",
        "wrong_audience_denied",
        "wrong_subject_denied",
        "invalid_signature_denied",
        "expiry_drains_live",
        "credential_tamper_drains",
        "socket_tamper_drains",
        "box_restart",
        "node_restart_drains",
        "agent_restart",
        "drain_preserves_state",
        "rollback_preserves_state",
        "native_a0_ui",
        "native_a0_websocket",
        "native_a0_message_loop",
        "native_sovereign_guest",
        "ui_gateway_ipv6_denied",
        "ui_gateway_dns_denied",
        "ui_initializer_caps_dropped",
    }
)


def validate_receipt(receipt, binaries, pack_hash, kernel, now=None, *, require_guest=True):
    import time

    now = time.time() if now is None else now
    blockers = []
    if receipt.get("schema") != 1:
        blockers.append("certification_schema_invalid")
    timestamp = receipt.get("generated_at", 0)
    if not isinstance(timestamp, (int, float)) or not 0 <= now - timestamp <= 86400:
        blockers.append("certification_stale")
    if receipt.get("kernel") != kernel:
        blockers.append("certification_host_mismatch")
    if receipt.get("binary_sha256") != binaries or receipt.get("pack_sha256") != pack_hash:
        blockers.append("certification_artifacts_mismatch")
    if receipt.get("supported") is not True:
        blockers.append("certification_not_supported")
    checks = receipt.get("checks", {})
    blockers.extend(
        name + "_unverified"
        for name in sorted(REQUIRED_RUNTIME_CHECKS)
        if checks.get(name) is not True and (require_guest or name != "native_sovereign_guest")
    )
    return blockers


def pack_sha256(root):
    from pathlib import Path

    root = Path(root)
    digest = hashlib.sha256()
    paths = []
    for directory in (
        "deploy",
        "helpers",
        "extensions",
        "api",
        "conf",
        "tools",
        "prompts",
        "skills",
        "webui",
    ):
        paths.extend((root / directory).rglob("*"))
    paths.extend(
        root / name for name in ("hooks.py", "execute.py", "plugin.yaml", "default_config.yaml")
    )
    paths = sorted(set(paths))
    for path in paths:
        if path.is_file() and "__pycache__" not in path.parts and path.suffix not in {".pyc"}:
            digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def certified_probe(receipt_path, binary_dir="/opt/sam", root=None):
    import json
    import os
    import platform
    import stat
    from pathlib import Path

    root = Path(root) if root else Path(__file__).resolve().parents[1]
    report = unavailable_report()
    try:
        path = Path(receipt_path)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("receipt permission check failed")
        binaries = {
            name: hashlib.sha256((Path(binary_dir) / name).read_bytes()).hexdigest()
            for name in ("sam-node", "sam-box", "nano-init")
        }
        receipt = json.loads(path.read_text())
        blockers = validate_receipt(receipt, binaries, pack_sha256(root), platform.release())
        if receipt.get("host_boot_id") != _boot_id():
            blockers.append("certification_host_boot_mismatch")
        if receipt.get("a0_source_sha256") != source_sha256("/a0"):
            blockers.append("certification_a0_source_mismatch")
        if receipt.get("image_reference") != os.environ.get("SOVEREIGN_RUNTIME_IMAGE"):
            blockers.append("certification_image_mismatch")
        if receipt.get("firewall_image_reference") != os.environ.get("SOVEREIGN_UI_IMAGE"):
            blockers.append("certification_ui_image_mismatch")
        report.update(
            supported=not blockers,
            posture="certified" if not blockers else "experimental",
            status="supported" if not blockers else "unsupported",
            blockers=blockers,
            network_enforcement_claimed=not blockers,
            binary_sha256=binaries,
            endpoint="http://mesh.sam.alt",
            boundary_socket="/run/sam-agent/agent.sock",
            ui_socket="/run/a0-ui/ui.sock",
            credential_rotation="stop-and-restart",
            secret_injection=False,
        )
    except (OSError, ValueError, TypeError, AttributeError):
        report["blockers"] = ["trusted_runtime_certification_required"]
    return report


def source_sha256(root):
    """Bind unmodified A0 core separately from mutable user/runtime/plugin state."""
    from pathlib import Path

    root = Path(root)
    if not (root / "agent.py").is_file() or not (root / "run_ui.py").is_file():
        raise ValueError("Agent Zero source is absent")
    if not all((root / "knowledge" / area).is_dir() for area in ("main", "fragments", "solutions")):
        raise ValueError(
            "Agent Zero knowledge directories must be prepared before mounting read-only"
        )
    digest = hashlib.sha256()
    import os

    paths = []
    for directory, directories, files in os.walk(root):
        relative_dir = Path(directory).relative_to(root)
        directories[:] = sorted(
            name
            for name in directories
            if name != "__pycache__"
            and (relative_dir.parts or name not in {"usr", "tmp", ".git", ".venv"})
        )
        paths.extend(Path(directory) / name for name in files if not name.endswith(".pyc"))
    for path in sorted(paths):
        relative = path.relative_to(root)
        digest.update(str(relative).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def _boot_id():
    from pathlib import Path

    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def _readonly_mount(path):
    from pathlib import Path

    path = str(Path(path).resolve())
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) > 5 and fields[4] == path:
            return "ro" in fields[5].split(",")
    return False


def guest_privileges_safe(status):
    """Only namespace-local TUN setup authority may remain in the guest."""
    try:
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        return fields.get("NoNewPrivs", "").strip() == "1" and all(
            int(fields[name].strip(), 16) & ~(1 << 12) == 0
            for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        )
    except (KeyError, ValueError):
        return False


def guest_probe(*, _certification_bootstrap=False):
    """Read public certification and inspect only guest-owned runtime surfaces."""
    import json
    import os
    import platform
    import socket
    import stat
    from pathlib import Path

    report = unavailable_report()
    report.update(endpoint="http://mesh.sam.alt", boundary_socket="/run/sam-agent/agent.sock")
    blockers = []
    try:
        path = Path("/run/sam-certification/receipt.json")
        if not _readonly_mount(path.parent) or not _readonly_mount("/run/sam-agent"):
            raise ValueError("guest proof and boundary mounts must be read-only")
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
            or metadata.st_size > 262144
        ):
            raise ValueError("receipt must be a bounded owner-only regular file")
        if not _readonly_mount("/a0"):
            raise ValueError("Agent Zero core source must be mounted read-only")
        receipt = json.loads(path.read_text())
        nano_hash = hashlib.sha256(Path("/opt/sam/nano-init").read_bytes()).hexdigest()
        binaries = receipt.get("binary_sha256", {})
        if binaries.get("nano-init") != nano_hash:
            blockers.append("guest_nano_init_mismatch")
        root = Path(__file__).resolve().parents[1]
        blockers.extend(
            validate_receipt(
                receipt,
                binaries,
                pack_sha256(root),
                platform.release(),
                require_guest=not (
                    _certification_bootstrap and receipt.get("purpose") == "guest_validation_only"
                ),
            )
        )
        if receipt.get("host_boot_id") != _boot_id():
            blockers.append("certification_host_boot_mismatch")
        if receipt.get("a0_source_sha256") != source_sha256("/a0"):
            blockers.append("certification_a0_source_mismatch")
        if {name for _, name in socket.if_nameindex()} != {"lo", "tun0"}:
            blockers.append("guest_interfaces_not_isolated")
        routes = Path("/proc/net/route").read_text().splitlines()[1:]
        defaults = [line.split()[0] for line in routes if line.split()[1] == "00000000"]
        if defaults != ["tun0"]:
            blockers.append("guest_default_route_invalid")
        # Every non-loopback IPv6 default with a real metric must use tun0.
        routes6 = [line.split() for line in Path("/proc/net/ipv6_route").read_text().splitlines()]
        defaults6 = [
            fields[-1]
            for fields in routes6
            if fields[0] == "0" * 32 and fields[1] == "00" and fields[-1] != "lo"
        ]
        if defaults6 != ["tun0"]:
            blockers.append("guest_ipv6_default_route_invalid")
        if not guest_privileges_safe(Path("/proc/self/status").read_text()):
            blockers.append("guest_privileges_not_confined")
        for forbidden in (
            "/run/sam-node",
            "/run/private",
            "/run/credentials",
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/run/containerd/containerd.sock",
        ):
            if Path(forbidden).exists():
                blockers.append("guest_node_authority_present")
        if os.environ.get("SAM_API_TOKEN"):
            blockers.append("guest_node_authority_present")
        metadata = Path(report["boundary_socket"]).lstat()
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
        ):
            raise ValueError("public boundary socket is not owner-only")
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(2)
            client.connect(report["boundary_socket"])
            client.sendall(b"CONNECT mesh.sam.alt:80 HTTP/1.1\r\nHost: mesh.sam.alt:80\r\n\r\n")
            response = b""
            while not response.endswith(b"\r\n\r\n") and len(response) < 8192:
                piece = client.recv(1)
                if not piece:
                    break
                response += piece
            if response.split(b"\r\n")[0].split()[1:2] != [b"200"]:
                blockers.append("guest_boundary_admission_failed")
    except (OSError, ValueError, TypeError, AttributeError, IndexError):
        blockers.append("trusted_guest_certification_required")
    report.update(
        supported=not blockers,
        posture="certified" if not blockers else "experimental",
        status="supported" if not blockers else "unsupported",
        blockers=sorted(set(blockers)),
        network_enforcement_claimed=not blockers,
    )
    return report
