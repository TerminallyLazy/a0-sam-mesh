#!/usr/bin/env python3
"""Bounded Compose lifecycle without removing user volumes or node identity."""

import argparse
import json
import os
import re
import socket
import subprocess
from pathlib import Path

PACK = Path(__file__).resolve().parents[2]
DEFAULT = PACK / "deploy/compose/docker-compose.sovereign.yml"


def compose(path, *args):
    return subprocess.run(
        ["docker", "compose", "-f", str(path), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
    ).stdout


def configuration(path):
    return json.loads(compose(path, "config", "--format", "json"))


def usr_volume(config):
    services = config["services"]
    mounts = [
        v
        for service in services.values()
        for v in service.get("volumes", [])
        if v.get("target") == "/a0/usr"
    ]
    if len(mounts) != 1 or mounts[0].get("type") != "volume":
        raise ValueError("exactly one explicit named /a0/usr volume is required")
    return config["volumes"][mounts[0]["source"]]["name"]


def disable_remote(path):
    code = """import contextlib,io,json
with contextlib.redirect_stdout(io.StringIO()):
    from helpers import plugins
    plugins.toggle_plugin('sam_mesh',False,clear_overrides=True)
    disabled = plugins.get_toggle_state('sam_mesh') == 'disabled'
print(json.dumps({'plugin_disabled':disabled,'scoped_toggles_cleared':True}))
if not disabled: raise SystemExit(1)
"""
    running = compose(path, "ps", "--status", "running", "--services").splitlines()
    if "agent-zero" in running:
        output = compose(
            path,
            "exec",
            "-T",
            "--workdir",
            "/a0",
            "agent-zero",
            "/opt/venv-a0/bin/python",
            "-c",
            code,
        )
    else:
        output = compose(
            path,
            "run",
            "--rm",
            "--no-deps",
            "--workdir",
            "/a0",
            "--entrypoint",
            "/opt/venv-a0/bin/python",
            "agent-zero",
            "-c",
            code,
        )
    return json.loads(output.strip().splitlines()[-1])


def drain(path, *, disable=True):
    errors = []
    if disable:
        try:
            disable_remote(path)
        except (ValueError, subprocess.SubprocessError) as exc:
            errors.append(exc)
    # Emergency closure still stops every boundary when the framework is broken.
    services = ["a0-ui-gateway", "agent-zero", "sam-box-a0", "sam-node"]
    if "a0-ui-network" in configuration(path)["services"]:
        services.append("a0-ui-network")
    for service in services:
        try:
            compose(path, "stop", "--timeout", "10", service)
        except subprocess.SubprocessError as exc:
            errors.append(exc)
    if errors:
        raise RuntimeError(
            "drain attempted every service; inspect Compose status before recovery"
        ) from errors[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["preflight", "drain", "rollback"])
    parser.add_argument("--compose", type=Path, default=DEFAULT)
    parser.add_argument("--ordinary-compose", type=Path)
    parser.add_argument("--export", type=Path)
    args = parser.parse_args()
    config = configuration(args.compose)
    if args.action == "preflight":
        for service in config["services"].values():
            if not re.fullmatch(r"(?:.+@)?sha256:[0-9a-f]{64}", service["image"]):
                raise ValueError("every image must be pinned by digest")
        agent = config["services"]["agent-zero"]
        if agent.get("network_mode") != "none":
            raise ValueError("agent network must be none")
        usr_volume(config)
        port = int(os.environ.get("A0_UI_PORT", "50080"))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", port))
        compose(args.compose, "run", "--rm", "--no-deps", "capability-gate")
        print("Preflight passed for exact certified runtime and available UI port")
    elif args.action == "drain":
        drain(args.compose)
        print("Drained; node identity and user volumes preserved")
    else:
        if args.ordinary_compose is None or args.export is None:
            raise ValueError("rollback requires explicit ordinary Compose and export paths")
        ordinary = configuration(args.ordinary_compose)
        if usr_volume(config) != usr_volume(ordinary):
            raise ValueError("rollback must use the same explicit usr volume")
        try:
            disabled = disable_remote(args.compose)
        except (ValueError, subprocess.SubprocessError):
            drain(args.compose, disable=False)
            raise RuntimeError(
                "remote disable failed; Sovereign stopped and ordinary startup refused"
            ) from None
        # Export metadata only: raw settings/audit can contain destinations or secrets.
        # The actual settings and audit remain intact on the shared usr volume.
        export = {
            "schema": 1,
            "usr_volume": usr_volume(config),
            "settings_and_audit": "preserved in usr volume",
            "node_identity": "preserved in node-state volume",
            "remote_features": disabled,
        }
        fd = os.open(args.export, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(export, stream, sort_keys=True)
        drain(args.compose, disable=False)
        compose(args.ordinary_compose, "up", "-d")
        print("Ordinary deployment started with same usr volume; node identity preserved")


if __name__ == "__main__":
    main()
