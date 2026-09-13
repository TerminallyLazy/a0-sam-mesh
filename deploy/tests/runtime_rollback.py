"""Exercise real Compose stop/start, native plugin disable, and unchanged volumes."""

import json
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path


def exercise(root, image, user_volume, source_volume, prefix):
    def docker(*args, check=True):
        return subprocess.run(
            ["docker", *args], check=check, text=True, capture_output=True, timeout=90
        ).stdout

    project = prefix + "-rollback"
    shared = {
        "user": {"external": True, "name": user_volume},
        "source": {"external": True, "name": source_volume},
        "node": {"name": project + "-node"},
    }
    agent = {
        "image": image,
        "network_mode": "none",
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "working_dir": "/a0",
        "entrypoint": ["/bin/sleep", "infinity"],
        "volumes": [
            "source:/a0:ro",
            "user:/a0/usr",
            str(root / "deploy/tests/native_loop.py") + ":/tmp/native-loop.py:ro",
        ],
        "tmpfs": ["/a0/tmp"],
    }
    quiet = {"image": image, "network_mode": "none", "entrypoint": ["/bin/sleep", "infinity"]}
    sovereign = {
        "name": project,
        "services": {
            "agent-zero": agent,
            "sam-box-a0": quiet,
            "sam-node": dict(quiet, volumes=["node:/state"]),
            "a0-ui-gateway": quiet,
        },
        "volumes": shared,
    }
    ordinary_agent = dict(
        agent,
        entrypoint=[
            "/opt/venv-a0/bin/python",
            "/a0/run_ui.py",
            "--dockerized=true",
            "--host=127.0.0.1",
            "--port=18091",
        ],
        environment={"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"},
    )
    ordinary = {
        "name": project + "-ordinary",
        "services": {"agent-zero": ordinary_agent},
        "volumes": shared,
    }
    with tempfile.TemporaryDirectory(prefix="sam-sovereign-rollback-") as directory:
        directory = Path(directory)
        sov = directory / "sovereign.json"
        ordinary_path = directory / "ordinary.json"
        export = directory / "redacted-export.json"
        sov.write_text(json.dumps(sovereign))
        ordinary_path.write_text(json.dumps(ordinary))

        def compose(path, *args):
            return docker("compose", "-f", str(path), *args)

        try:
            compose(sov, "up", "-d")
            container = compose(sov, "ps", "-q", "agent-zero").strip()
            docker("exec", container, "mkdir", "-p", "/a0/usr/plugins/sam_mesh")
            archive = directory / "plugin.tar"
            with tarfile.open(archive, "w") as bundle:
                for name in (
                    "plugin.yaml",
                    "default_config.yaml",
                    "hooks.py",
                    "execute.py",
                    "helpers",
                    "api",
                    "extensions",
                    "conf",
                    "prompts",
                    "tools",
                    "webui",
                ):
                    bundle.add(
                        root / name,
                        arcname=name,
                        filter=lambda item: None if "__pycache__" in item.name.split("/") else item,
                    )
            with archive.open("rb") as bundle:
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        "-i",
                        container,
                        "tar",
                        "-x",
                        "--no-same-owner",
                        "-C",
                        "/a0/usr/plugins/sam_mesh",
                    ],
                    stdin=bundle,
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            docker("exec", container, "chmod", "755", "/a0/usr", "/a0/usr/plugins")
            compose(
                sov,
                "exec",
                "-T",
                "agent-zero",
                "/opt/venv-a0/bin/python",
                "-c",
                "from helpers import plugins; from pathlib import Path; plugins.toggle_plugin('sam_mesh',True); Path('/a0/usr/sovereign-preserve').write_text('user data survives')",
            )
            compose(
                sov,
                "exec",
                "-T",
                "sam-node",
                "/bin/sh",
                "-c",
                "printf '%s' identity-state-preserved > /state/identity-sentinel",
            )
            subprocess.run(
                [
                    "python3",
                    str(root / "deploy/scripts/lifecycle.py"),
                    "rollback",
                    "--compose",
                    str(sov),
                    "--ordinary-compose",
                    str(ordinary_path),
                    "--export",
                    str(export),
                ],
                check=True,
                text=True,
                capture_output=True,
                timeout=90,
            )
            for _ in range(60):
                native = subprocess.run(
                    [
                        "docker",
                        "compose",
                        "-f",
                        str(ordinary_path),
                        "exec",
                        "-T",
                        "agent-zero",
                        "/opt/venv-a0/bin/python",
                        "-c",
                        "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:18091/',timeout=2).status == 200",
                    ],
                    capture_output=True,
                    timeout=5,
                )
                if native.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("ordinary native Agent Zero did not become ready after rollback")
            native_loop = compose(
                ordinary_path,
                "exec",
                "-T",
                "--env",
                "PYTHONPATH=/a0",
                "agent-zero",
                "/opt/venv-a0/bin/python",
                "/tmp/native-loop.py",
                "--dockerized=true",
            )
            native_loop = json.loads(native_loop.strip().splitlines()[-1])
            result = compose(
                ordinary_path,
                "exec",
                "-T",
                "agent-zero",
                "/opt/venv-a0/bin/python",
                "-c",
                "import json; from pathlib import Path; from helpers import plugins; print(json.dumps({'disabled':plugins.get_toggle_state('sam_mesh')=='disabled','user':Path('/a0/usr/sovereign-preserve').read_text()=='user data survives'}))",
            )
            result = json.loads(result.strip().splitlines()[-1])
            node = docker(
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                project + "-node:/state:ro",
                "--entrypoint",
                "cat",
                image,
                "/state/identity-sentinel",
            ).strip()
            receipt = json.loads(export.read_text())
            stopped = not compose(sov, "ps", "--status", "running", "--services").strip()
            return {
                "native_a0_message_loop": native_loop.get("native_a0_message_loop") is True,
                "rollback_preserves_state": (
                    result["disabled"]
                    and result["user"]
                    and node == "identity-state-preserved"
                    and stopped
                    and receipt["remote_features"]["plugin_disabled"]
                ),
            }
        finally:
            compose(ordinary_path, "down")
            compose(sov, "down")
            docker("volume", "rm", project + "-node", check=False)
