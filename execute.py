"""Short, idempotent diagnostics. Never install, join, reset, or start a daemon."""

import argparse
import json
import shutil
import stat
import subprocess
from pathlib import Path


def local_diagnostics(socket_path="/var/run/sam/node.sock"):
    binary = shutil.which("sam-node")
    version = None
    if binary:
        try:
            result = subprocess.run(
                [binary, "--version"], capture_output=True, text=True, timeout=3, check=False
            )
            # Only report a bounded version prefix, never arbitrary diagnostic output.
            first = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
            version = first[:120] if first.startswith(("sam-node ", "sam-node version ")) else None
        except (OSError, subprocess.TimeoutExpired):
            pass
    socket_ok = False
    try:
        metadata = Path(socket_path).lstat()
        socket_ok = stat.S_ISSOCK(metadata.st_mode) and not metadata.st_mode & 0o022
    except OSError:
        pass
    return {
        "binary_detected": bool(binary),
        "version": version,
        "socket_exists": socket_ok,
        "enrollment_performed": False,
        "status": "partial",
        "guidance": "Use the Observatory for an authenticated health probe. On uninstall, "
        "withdraw owned services and revoke leases; preserve SAM node identity.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket-path", default="/var/run/sam/node.sock")
    args = parser.parse_args()
    report = local_diagnostics(args.socket_path)
    print(json.dumps(report))
    return 0 if report["socket_exists"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
