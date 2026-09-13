#!/usr/bin/env python3
"""Disposable actual-binary Linux certification. A failed probe never emits support.

Run on the deployment host, or use CI results as version evidence only. All Docker
objects have an exclusive random sam-stable-sovereign prefix and are removed.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PYTHON = "/opt/venv-a0/bin/python"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--firewall-image", required=True)
    parser.add_argument("--a0-source-tar", type=Path, required=True)
    parser.add_argument(
        "--adapter-only",
        action="store_true",
        help="diagnose UDS adapters; never certifies TUN or support",
    )
    args = parser.parse_args()
    if "@sha256:" not in args.image:
        parser.error("image must be pinned by digest")
    args.binary_dir = args.binary_dir.resolve()
    args.a0_source_tar = args.a0_source_tar.resolve()
    for name in ("sam-node", "sam-box", "sam-one", "nano-init"):
        if not (args.binary_dir / name).is_file():
            parser.error("published binaries are missing")
    cert_spec = importlib.util.spec_from_file_location(
        "sovereign_initial", ROOT / "helpers/sovereign.py"
    )
    cert_module = importlib.util.module_from_spec(cert_spec)
    cert_spec.loader.exec_module(cert_module)
    initial_pack_hash = cert_module.pack_sha256(ROOT)
    initial_binaries = {
        name: hashlib.sha256((args.binary_dir / name).read_bytes()).hexdigest()
        for name in ("sam-node", "sam-box", "nano-init")
    }
    prefix = "sam-stable-sovereign-" + uuid.uuid4().hex[:10]
    infra = prefix + "-infra"
    agent = prefix + "-agent"
    gateway = prefix + "-gateway"
    firewall = prefix + "-firewall"
    avol = prefix + "-agent"
    uvol = prefix + "-ui"
    unet = prefix + "-ui"
    uservol = prefix + "-user"
    sourcevol = prefix + "-source"
    certvol = prefix + "-certification"
    containers = []
    volumes = []
    networks = []
    checks = {}
    evidence = {}

    def run(*command, check=True, timeout=60):
        value = subprocess.run(list(command), text=True, capture_output=True, timeout=timeout)
        if check and value.returncode:
            raise RuntimeError("command failed: " + command[0] + " " + value.stderr[-1000:])
        return value

    def docker(*command, **kw):
        return run("docker", *command, **kw)

    def execute(container, code):
        return docker("exec", container, PYTHON, "-c", code).stdout.strip()

    def action(action, *extra):
        return docker("exec", infra, PYTHON, "/pack/deploy/tests/runtime_infra.py", action, *extra)

    def wait_socket(present=True, timeout=20):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            result = (
                execute(
                    infra,
                    "from pathlib import Path; print(Path('/run/sam-agent/agent.sock').exists())",
                )
                == "True"
            )
            if result == present:
                return True
            time.sleep(0.2)
        return False

    def launch_boundary(credential="valid.jwt"):
        action("stop-boundary")
        action("bundle", "--credential", credential)
        action("boundary")
        return wait_socket()

    try:
        for volume in (avol, uvol, uservol, sourcevol, certvol):
            docker("volume", "create", volume)
            volumes.append(volume)
        docker("network", "create", unet)
        networks.append(unet)
        containers.append(infra)
        docker(
            "run",
            "-d",
            "--name",
            infra,
            "--add-host",
            "allowed.test:127.0.0.1",
            "-v",
            str(ROOT) + ":/pack:ro",
            "-v",
            str(args.binary_dir) + ":/opt/sam:ro",
            "-v",
            avol + ":/run/sam-agent",
            "-v",
            certvol + ":/certification",
            "--entrypoint",
            "/bin/sleep",
            args.image,
            "infinity",
        )
        action("initial")
        # Calibrate both external witnesses before the guest sends any probes.
        execute(
            infra,
            "import socket\nfor port in (18082,53):\n s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b'calibration',('127.0.0.1',port)); assert s.recv(128)==b'calibration'; s.close()",
        )
        if not wait_socket():
            raise RuntimeError("verified boundary did not become ready")
        evidence["kernel"] = execute(infra, "import platform; print(platform.release())")
        evidence["host_boot_id"] = execute(
            infra,
            "from pathlib import Path; print(Path('/proc/sys/kernel/random/boot_id').read_text().strip())",
        )
        evidence["docker"] = docker("version", "--format", "{{.Server.Version}}").stdout.strip()
        ip = json.loads(docker("inspect", infra).stdout)[0]["NetworkSettings"]["Networks"][
            "bridge"
        ]["IPAddress"]
        containers.append(agent)
        command = [
            "run",
            "-d",
            "--name",
            agent,
            "--network",
            "none",
            "--device",
            "/dev/net/tun",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "NET_ADMIN",
            "--security-opt",
            "no-new-privileges=true",
            "-v",
            avol + ":/run/sam-agent:ro",
            "-v",
            uvol + ":/run/a0-ui",
            "-v",
            sourcevol + ":/a0",
            "-v",
            uservol + ":/a0/usr",
            "-v",
            str(args.binary_dir / "nano-init") + ":/nano-init:ro",
            "--entrypoint",
            "/bin/sleep",
            args.image,
            "infinity",
        ]
        docker(*command)
        docker("cp", str(ROOT / "deploy/tests/runtime_probe.py"), agent + ":/tmp/probe.py")
        if args.adapter_only:
            probe = docker(
                "exec", agent, PYTHON, "/tmp/probe.py", "adapter", "--infra-ip", ip, check=False
            )
        else:
            docker(
                "exec",
                "-d",
                agent,
                "/bin/sh",
                "-c",
                "/nano-init run /run/sam-agent/agent.sock /bin/sleep infinity > /tmp/nano.log 2>&1",
            )
            time.sleep(1)
            probe = docker(
                "exec",
                agent,
                PYTHON,
                "/tmp/probe.py",
                "network",
                "--infra-ip",
                ip,
                check=False,
                timeout=60,
            )
            evidence["nano_init"] = execute(
                agent, "from pathlib import Path; print(Path('/tmp/nano.log').read_text())"
            )
        evidence["network_probe"] = probe.stderr[-4000:]
        if probe.returncode == 0:
            observed = json.loads(probe.stdout)
            evidence["request_diagnostics"] = observed.pop("_diagnostics", [])
            evidence["adapter_checks"] = observed
            if not args.adapter_only:
                checks.update(observed)
            else:
                checks.update(
                    {
                        name: observed[name]
                        for name in (
                            "node_authority_absent",
                            "socket_separation",
                            "mesh_admin_denied",
                        )
                    }
                )
        else:
            checks["tun_real"] = False
        if checks.get("tun_real"):
            checks["udp_denied"] = (
                checks.get("udp_protocol_denied")
                and execute(
                    infra,
                    "from pathlib import Path; print(Path('/fixture/udp-witness.log').read_bytes()==b'calibration\\n')",
                )
                == "True"
            )
            checks["dns_no_external_packets"] = (
                execute(
                    infra,
                    "from pathlib import Path; print(Path('/fixture/dns-witness.log').read_bytes()==b'calibration\\n')",
                )
                == "True"
            )
        # Actual verified startup refusals, never simulated identity acceptance.
        for credential, name in [
            ("missing.jwt", "missing_credential_denied"),
            ("expired.jwt", "expired_credential_denied"),
            ("wrong.jwt", "wrong_audience_denied"),
            ("wrong-subject.jwt", "wrong_subject_denied"),
            ("invalid-signature.jwt", "invalid_signature_denied"),
        ]:
            action("stop-boundary")
            action("bundle", "--credential", credential)
            action("boundary")
            time.sleep(1)
            checks[name] = wait_socket(False, timeout=2)
        if not launch_boundary():
            raise RuntimeError("boundary failed to recover")
        execute(
            infra,
            "from pathlib import Path; p=Path('/fixture/valid.jwt'); p.write_bytes(p.read_bytes()+b' ')",
        )
        checks["credential_tamper_drains"] = wait_socket(False, timeout=3)
        if not launch_boundary():
            raise RuntimeError("boundary failed after credential replacement")
        execute(infra, "import os; os.chmod('/run/sam-agent/agent.sock',0o666)")
        checks["socket_tamper_drains"] = wait_socket(False, timeout=3)
        checks["box_restart"] = launch_boundary()
        action("stop-node")
        checks["node_restart_drains"] = wait_socket(False, timeout=3)
        action("node")
        if not launch_boundary():
            raise RuntimeError("boundary failed after node restart")
        execute(
            infra,
            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:18081/issue-short').close()",
        )
        ready = launch_boundary("short.jwt")
        live_closed = (
            execute(
                agent,
                "import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(12); s.connect('/run/sam-agent/agent.sock'); s.sendall(b'CONNECT allowed.test:18081 HTTP/1.1\\r\\nHost: allowed.test:18081\\r\\n\\r\\n'); response=s.recv(1024); assert b'200' in response; print(s.recv(1)==b'')",
            )
            == "True"
            if ready
            else False
        )
        checks["expiry_drains_live"] = ready and live_closed and wait_socket(False, timeout=3)
        if not launch_boundary():
            raise RuntimeError("boundary failed after expiry")
        # UI bridge runs in an agent with no network. A real WebSocket byte exchange
        # exercises the transport; application authentication stays in Agent Zero.
        docker("cp", str(ROOT / "deploy/scripts/ui-bridge.py"), agent + ":/tmp/ui-bridge.py")
        docker("cp", str(ROOT / "deploy/tests/ui_fixture.py"), agent + ":/tmp/ui-fixture.py")
        docker("exec", "-d", agent, PYTHON, "/tmp/ui-fixture.py")
        docker("exec", "-d", agent, PYTHON, "/tmp/ui-bridge.py", "sandbox", "--port", "18090")
        containers.append(firewall)
        docker(
            "run",
            "-d",
            "--name",
            firewall,
            "--network",
            unet,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "NET_ADMIN",
            "--cap-add",
            "SETPCAP",
            "--security-opt",
            "no-new-privileges=true",
            "-p",
            "127.0.0.1::8080",
            "--tmpfs",
            "/run",
            "-v",
            str(ROOT / "deploy/scripts/ui-network.sh") + ":/ui-network.sh:ro",
            "--entrypoint",
            "/bin/sh",
            args.firewall_image,
            "/ui-network.sh",
        )
        time.sleep(1)
        if docker("exec", firewall, "test", "-f", "/run/firewall-ready", check=False).returncode:
            raise RuntimeError("firewall initialization failed")
        evidence["firewall_image"] = json.loads(docker("inspect", firewall).stdout)[0]["Image"]
        containers.append(gateway)
        docker(
            "run",
            "-d",
            "--name",
            gateway,
            "--network",
            "container:" + firewall,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "-v",
            uvol + ":/run/a0-ui:ro",
            "-v",
            str(ROOT / "deploy/scripts/ui-bridge.py") + ":/ui-bridge.py:ro",
            "--entrypoint",
            PYTHON,
            args.image,
            "/ui-bridge.py",
            "gateway",
            "--port",
            "8080",
        )
        time.sleep(1)
        info = json.loads(docker("inspect", firewall).stdout)[0]
        port = int(info["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"])
        import socket

        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            checks["ui_reachable"] = b"200" in s.recv(4096)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(
                b"GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            checks["ui_websocket"] = b"101" in s.recv(4096)
            s.sendall(b"\x81\x82abcd" + bytes([ord("o") ^ ord("a"), ord("k") ^ ord("b")]))
            checks["ui_websocket"] &= s.recv(1024) == b"\x81\x02ok"
        checks["ui_gateway_no_egress"] = (
            execute(
                gateway,
                "import socket; s=socket.socket(); s.settimeout(2)\ntry: s.connect(('1.1.1.1',443)); print(False)\nexcept OSError: print(True)",
            )
            == "True"
        )
        checks["socket_separation"] &= (
            execute(
                gateway,
                "from pathlib import Path; print(not any(Path(p).exists() for p in ['/run/sam-agent','/run/sam-node','/a0/usr']))",
            )
            == "True"
        )
        # Replace the byte witness with unmodified Agent Zero and exercise its
        # protected HTTP and real Engine.IO WebSocket surface through the same UDS.
        docker(
            "exec", agent, "pkill", "-f", "^/opt/venv-a0/bin/python /tmp/ui-fixture.py", check=False
        )
        docker("cp", str(args.a0_source_tar), agent + ":/tmp/a0-source.tar.gz")
        docker(
            "exec",
            agent,
            "tar",
            "-xzf",
            "/tmp/a0-source.tar.gz",
            "--strip-components=1",
            "--no-same-owner",
            "-C",
            "/a0",
        )
        docker("exec", agent, "chmod", "755", "/a0/usr", "/a0/usr/plugins")
        docker(
            "exec",
            agent,
            "mkdir",
            "-p",
            "/a0/knowledge/main",
            "/a0/knowledge/fragments",
            "/a0/knowledge/solutions",
        )
        docker(
            "exec",
            "-d",
            "-w",
            "/a0",
            "-e",
            "HF_HUB_OFFLINE=1",
            "-e",
            "TRANSFORMERS_OFFLINE=1",
            agent,
            "/bin/sh",
            "-c",
            "/opt/venv-a0/bin/python /a0/run_ui.py --dockerized=true --host=127.0.0.1 --port=18090 > /tmp/a0-native.log 2>&1",
        )
        import urllib.request

        for _ in range(90):
            try:
                with urllib.request.urlopen(
                    "http://127.0.0.1:" + str(port) + "/", timeout=2
                ) as response:
                    checks["native_a0_ui"] = (
                        response.status == 200 and b"Agent Zero" in response.read()
                    )
                    if checks["native_a0_ui"]:
                        break
            except OSError:
                time.sleep(1)
        else:
            checks["native_a0_ui"] = False
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(
                b"GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            checks["native_a0_websocket"] = b"101" in s.recv(4096)
        evidence["a0_source_archive_sha256"] = hashlib.sha256(
            args.a0_source_tar.read_bytes()
        ).hexdigest()
        docker("cp", str(ROOT / "helpers/sovereign.py"), agent + ":/tmp/sovereign-proof.py")
        evidence["a0_source_sha256"] = execute(
            agent,
            "import runpy; print(runpy.run_path('/tmp/sovereign-proof.py')['source_sha256']('/a0'))",
        )
        checks["ui_gateway_ipv6_denied"] = (
            execute(
                gateway,
                "import socket; s=socket.socket(socket.AF_INET6); s.settimeout(2)\ntry: s.connect(('2606:4700:4700::1111',443)); print(False)\nexcept OSError: print(True)",
            )
            == "True"
        )
        checks["ui_gateway_dns_denied"] = (
            execute(
                gateway,
                "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(1)\ntry: s.sendto(b'blocked-dns',('127.0.0.11',53)); s.recv(1024); print(False)\nexcept OSError: print(True)",
            )
            == "True"
        )
        checks["ui_initializer_caps_dropped"] = (
            execute(
                firewall,
                "from pathlib import Path; print(all(int(line.split()[1],16)==0 for line in Path('/proc/1/status').read_text().splitlines() if line.startswith(('CapInh:','CapPrm:','CapEff:','CapBnd:','CapAmb:'))))",
            )
            == "True"
        )
        # Restart a fresh agent namespace (nano-init is intentionally not re-run in
        # a live namespace whose routes already exist).
        docker("restart", agent)
        if not args.adapter_only:
            docker(
                "exec",
                "-d",
                agent,
                "/nano-init",
                "run",
                "/run/sam-agent/agent.sock",
                "/bin/sleep",
                "infinity",
            )
            time.sleep(1)
            replay = docker(
                "exec", agent, PYTHON, "/tmp/probe.py", "network", "--infra-ip", ip, check=False
            )
            checks["agent_restart"] = replay.returncode == 0 and json.loads(replay.stdout).get(
                "tun_real", False
            )
        before = execute(
            infra,
            "import pathlib,hashlib,json; print(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in pathlib.Path('/fixture/node-state').rglob('*') if p.is_file()},sort_keys=True))",
        )
        action("stop-boundary")
        action("stop-node")
        after = execute(
            infra,
            "import pathlib,hashlib,json; print(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in pathlib.Path('/fixture/node-state').rglob('*') if p.is_file()},sort_keys=True))",
        )
        checks["drain_preserves_state"] = before == after and bool(json.loads(before))
        # Exercise actual native plugin disable and ordinary Compose startup with
        # unchanged named volumes; no mocked Docker command can satisfy this gate.
        spec = importlib.util.spec_from_file_location(
            "runtime_rollback", ROOT / "deploy/tests/runtime_rollback.py"
        )
        rollback = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(rollback)
        checks.update(rollback.exercise(ROOT, args.image, uservol, sourcevol, prefix))
        baseline_checks = cert_module.REQUIRED_RUNTIME_CHECKS - {"native_sovereign_guest"}
        if not args.adapter_only and all(checks.get(name) is True for name in baseline_checks):
            # This private baseline proves the already completed network matrix.
            # It lacks native_sovereign_guest, so the operator deployment gate
            # refuses it. No bootstrap receipt is exported or retained.
            baseline = {
                "schema": 1,
                "supported": True,
                "purpose": "guest_validation_only",
                "generated_at": time.time(),
                "kernel": evidence["kernel"],
                "host_boot_id": evidence["host_boot_id"],
                "a0_source_sha256": evidence["a0_source_sha256"],
                "binary_sha256": initial_binaries,
                "pack_sha256": initial_pack_hash,
                "image_reference": args.image,
                "firewall_image_reference": args.firewall_image,
                "checks": dict(checks),
            }
            execute(
                infra,
                "import pathlib,os; p=pathlib.Path('/certification/receipt.json'); p.write_text("
                + repr(json.dumps(baseline))
                + "); p.chmod(0o600)",
            )
            action("node")
            if not launch_boundary():
                raise RuntimeError("verified boundary restart failed before native guest proof")
            guest = prefix + "-native-guest"
            containers.append(guest)
            guest_launch = [
                "run",
                "-d",
                "--name",
                guest,
                "--network",
                "none",
                "--device",
                "/dev/net/tun",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "NET_ADMIN",
                "--security-opt",
                "no-new-privileges=true",
                "-v",
                avol + ":/run/sam-agent:ro",
                "-v",
                certvol + ":/run/sam-certification:ro",
                "-v",
                sourcevol + ":/a0:ro",
                "-v",
                uservol + ":/a0/usr",
                "--tmpfs",
                "/a0/tmp",
                "-v",
                str(args.binary_dir / "nano-init") + ":/opt/sam/nano-init:ro",
                "-v",
                str(ROOT / "deploy/tests/native_guest.py") + ":/native-guest.py:ro",
                "-w",
                "/a0",
                "-e",
                "PYTHONPATH=/a0",
                "-e",
                "HF_HUB_OFFLINE=1",
                "-e",
                "TRANSFORMERS_OFFLINE=1",
                "-e",
                "LITELLM_LOCAL_MODEL_COST_MAP=True",
                "--entrypoint",
                "/bin/sleep",
                args.image,
                "infinity",
            ]
            docker(*guest_launch)
            result = docker(
                "exec",
                guest,
                "/opt/sam/nano-init",
                "run",
                "/run/sam-agent/agent.sock",
                PYTHON,
                "/native-guest.py",
                "--dockerized=true",
                check=False,
                timeout=150,
            )
            if result.returncode != 0:
                evidence["native_guest_error"] = (result.stdout + result.stderr)[-5000:]
                checks["native_sovereign_guest"] = False
            else:
                native = json.loads(result.stdout.strip().splitlines()[-1])
                evidence["native_guest"] = native
                witnessed = (
                    execute(
                        infra,
                        "from pathlib import Path; print(Path('/fixture/model-witness.log').read_text().count('native-model-request') == 1)",
                    )
                    == "True"
                )
                checks["native_sovereign_guest"] = (
                    native.get("native_sovereign_guest") is True and witnessed
                )
            if checks.get("native_sovereign_guest") is True:
                baseline.update(purpose="runtime_certification", checks=dict(checks))
                execute(
                    infra,
                    "from pathlib import Path; Path('/certification/receipt.json').write_text("
                    + repr(json.dumps(baseline))
                    + ")",
                )
                # Fresh process AND namespace, no bootstrap wrapper: exercise the
                # same strict guest gate and native config used in production.
                final_guest = prefix + "-final-guest"
                containers.append(final_guest)
                guest_launch[3] = final_guest
                docker(*guest_launch)
                final_result = docker(
                    "exec",
                    final_guest,
                    "/opt/sam/nano-init",
                    "run",
                    "/run/sam-agent/agent.sock",
                    PYTHON,
                    "/native-guest.py",
                    "--dockerized=true",
                    "--final-validation",
                    check=False,
                    timeout=150,
                )
                if final_result.returncode:
                    checks["native_sovereign_guest"] = False
                    evidence["native_guest_strict_error"] = (
                        final_result.stdout + final_result.stderr
                    )[-5000:]
                else:
                    strict_result = json.loads(final_result.stdout.strip().splitlines()[-1])
                    evidence["native_guest_strict"] = strict_result
                    checks["native_sovereign_guest"] = (
                        strict_result.get("native_sovereign_guest") is True
                        and strict_result.get("strict_guest_probe") is True
                    )
            execute(
                infra,
                "from pathlib import Path; Path('/certification/receipt.json').unlink(missing_ok=True)",
            )

    except Exception as exc:
        evidence["failure"] = str(exc)[:2000]
    finally:
        for container in reversed(containers):
            docker("rm", "-f", container, check=False)
        for network in networks:
            docker("network", "rm", network, check=False)
        for volume in volumes:
            docker("volume", "rm", volume, check=False)
    spec = importlib.util.spec_from_file_location("sovereign", ROOT / "helpers/sovereign.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report = {
        "schema": 1,
        "generated_at": time.time(),
        "kernel": evidence.get("kernel"),
        "host_boot_id": evidence.get("host_boot_id"),
        "a0_source_sha256": evidence.get("a0_source_sha256"),
        "binary_sha256": {
            name: hashlib.sha256((args.binary_dir / name).read_bytes()).hexdigest()
            for name in ("sam-node", "sam-box", "nano-init")
        },
        "pack_sha256": module.pack_sha256(ROOT),
        "checks": checks,
        "evidence": evidence,
    }
    if initial_pack_hash != report["pack_sha256"] or initial_binaries != report["binary_sha256"]:
        evidence["failure"] = (
            "certification inputs changed during execution; rerun against frozen files"
        )
    report["image_reference"] = args.image
    report["firewall_image_reference"] = args.firewall_image
    report["supported"] = (
        not args.adapter_only
        and not evidence.get("failure")
        and all(checks.get(name) is True for name in module.REQUIRED_RUNTIME_CHECKS)
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(report, output, indent=2, sort_keys=True)
    print(
        json.dumps(
            {
                "supported": report["supported"],
                "checks": checks,
                "failure": evidence.get("failure"),
                "receipt": str(args.output),
            }
        )
    )
    return 0 if report["supported"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
