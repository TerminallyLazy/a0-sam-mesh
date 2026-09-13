"""All credentials/state are ephemeral inside an explicitly disposable container."""

import argparse
import json
import os
import secrets
import signal
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT = Path("/fixture")
ROOT.mkdir(exist_ok=True, mode=0o700)
BIN = Path("/opt/sam")
PACK = Path("/pack")


def start(name, command, env=None):
    log = open(ROOT / (name + ".log"), "ab")
    proc = subprocess.Popen(command, stdout=log, stderr=log, env=env)
    (ROOT / (name + ".pid")).write_text(str(proc.pid))
    return proc


def stop(name):
    path = ROOT / (name + ".pid")
    if path.exists():
        try:
            os.kill(int(path.read_text()), signal.SIGTERM)
        except ProcessLookupError:
            pass
    time.sleep(1)


def bundle(credential):
    path = ROOT / "bundle.yaml"
    path.write_text(
        "version: v1\nagent:\n  id: a0.cert.test\n  external_id: a0-cert\n  credential: /fixture/"
        + credential
        + "\negress:\n  allow: [allowed.test]\n"
    )
    path.chmod(0o600)


def boundary():
    start(
        "boundary",
        [
            "/opt/venv-a0/bin/python",
            str(PACK / "deploy/scripts/boundary.py"),
            "--bundle",
            "/fixture/bundle.yaml",
            "--issuer",
            "http://127.0.0.1:18081",
            "--audience",
            "sovereign-cert",
            "--node-socket",
            "/run/sam-node/node.sock",
            "--socket",
            "/run/sam-agent/agent.sock",
        ],
    )


def node():
    args = [
        str(BIN / "sam-node"),
        "run",
        "--bind-addr=",
        "--socket-path",
        "/run/sam-node/node.sock",
        "--data-dir",
        "/fixture/node-state",
        "--config",
        "/fixture/node.yaml",
        "--control-plane",
        "http://127.0.0.1:18080",
        "--allow-loopback",
    ]
    if not (ROOT / "enrolled").exists():
        args += ["--bootstrap-token-path", "/fixture/join-token"]
    start("node", args)
    for _ in range(100):
        if Path("/run/sam-node/node.sock").exists():
            (ROOT / "enrolled").touch()
            return
        time.sleep(0.1)
    raise SystemExit("node did not create its socket")


def initial():
    for path in ("/run/sam-node", "/run/sam-agent"):
        Path(path).mkdir(exist_ok=True, mode=0o700)
        os.chmod(path, 0o700)
    env = dict(os.environ, FIXTURE_ROOT="/fixture")
    start("issuer", ["/opt/venv-a0/bin/python", str(PACK / "deploy/tests/runtime_fixture.py")], env)
    token = secrets.token_urlsafe(32)
    (ROOT / "join-token").write_text(token)
    (ROOT / "join-token").chmod(0o600)
    policy = {
        "roles": [
            {"name": "sam:role:router", "allowedServices": ["*"], "allowedTargets": ["*"]},
            {
                "name": "sam:role:node",
                "allowedServices": ["mcp://sovereign_probe"],
                "allowedTargets": ["*"],
                "allowedAgents": ["a0.cert.test"],
                "customDatalog": ['granted_agent_exact("a0.cert.test")'],
            },
        ]
    }
    (ROOT / "policy.json").write_text(json.dumps(policy))
    env = dict(os.environ, SAM_TOKEN=token)
    start(
        "one",
        [
            str(BIN / "sam-one"),
            "--port",
            "18080",
            "--external-url",
            "http://127.0.0.1:18080",
            "--data-dir",
            "/fixture/one-state",
            "--policy-file",
            "/fixture/policy.json",
        ],
        env,
    )
    for _ in range(100):
        try:
            urllib.request.urlopen("http://127.0.0.1:18080/info", timeout=1).close()
            urllib.request.urlopen("http://127.0.0.1:18081/keys", timeout=1).close()
            break
        except Exception:
            time.sleep(0.1)
    else:
        raise SystemExit("fixture endpoints unavailable")
    (ROOT / "node.yaml").write_text("version: v1alpha1\nservices: []\n")
    (ROOT / "provider.yaml").write_text(
        "version: v1alpha1\nservices:\n  - type: mcp\n    name: sovereign_probe\n    target_url: http://127.0.0.1:18081/mcp\n"
    )
    Path("/run/sam-provider").mkdir(mode=0o700, exist_ok=True)
    start(
        "provider",
        [
            str(BIN / "sam-node"),
            "run",
            "--bind-addr=",
            "--socket-path",
            "/run/sam-provider/provider.sock",
            "--data-dir",
            "/fixture/provider-state",
            "--config",
            "/fixture/provider.yaml",
            "--control-plane",
            "http://127.0.0.1:18080",
            "--bootstrap-token-path",
            "/fixture/join-token",
            "--listen",
            "/ip4/127.0.0.1/tcp/5004",
            "--allow-loopback",
            "--discovery-interval",
            "1s",
        ],
    )
    node()
    bundle("valid.jwt")
    boundary()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument(
        "action", choices=["initial", "boundary", "node", "stop-boundary", "stop-node", "bundle"]
    )
    p.add_argument("--credential", default="valid.jwt")
    a = p.parse_args()
    if a.action == "initial":
        initial()
    elif a.action == "boundary":
        boundary()
    elif a.action == "node":
        node()
    elif a.action.startswith("stop-"):
        stop(a.action[5:])
    else:
        bundle(a.credential)
