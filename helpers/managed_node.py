"""Private loopback SAM runtime, owned by native plugin lifecycle hooks."""

from __future__ import annotations

import atexit
import fcntl
import hashlib
import json
import os
import platform
import secrets
import socket
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

VERSION = "v0.1.0-alpha.9"
ARCHIVES = {
    "aarch64": ("arm64", "cf0d2ae56674ba5a4f57165285b230da602a637dc698109145a8a0a0f688b02d"),
    "x86_64": ("x86_64", "4ed7dbc055904a02ce6ca5c32bcc30f396bc56e404e3ce2f04bc81dee0fe02e9"),
}

BINARY_HASHES = {
    "arm64": {
        "sam-one": "975e54fca04968e16afb738b75ad41e8eec1574ddbc7e1702d904dd89c91984a",
        "sam-node": "df3f91eae31f2d32f7c82b5fd6b8b96edf1c660accd233fd4c8edacfd9b5ba3a",
    },
    "x86_64": {
        "sam-one": "d4f9dd9b2a8b573ccf7f73532e82b6279f9a15cf694993170680fde29f58697d",
        "sam-node": "6cb307f1bc768dd7b27879960ba4292af63860a5ae645d3f26b2bf685a079707",
    },
}


def _private_dir(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise RuntimeError("unsafe_runtime_storage")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(part, flags, dir_fd=parent)
            except FileNotFoundError:
                try:
                    os.mkdir(part, 0o700, dir_fd=parent)
                except FileExistsError:
                    pass
                child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            if info.st_uid not in {0, os.geteuid()} or (
                info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX
            ):
                raise RuntimeError("unsafe_runtime_storage")
        if os.fstat(parent).st_uid != os.geteuid():
            raise RuntimeError("unsafe_runtime_storage")
        os.fchmod(parent, 0o700)
    except OSError:
        raise RuntimeError("unsafe_runtime_storage") from None
    finally:
        os.close(parent)
    return path


def _read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise RuntimeError("unsafe_runtime_storage")
        data = stream.read(65537)
        if len(data) > 65536:
            raise RuntimeError("unsafe_runtime_storage")
        return data


def _write(path, data):
    fd, name = tempfile.mkstemp(prefix=".sam-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class ManagedNode:
    def __init__(self, root, *, archive_source=None):
        self.root = Path(root)
        self.archive_source = archive_source
        self.thread = None
        self.guard = threading.Lock()
        self.stop_event = threading.Event()
        self.lock = None
        self.children = []
        atexit.register(self.close)

    def status(self):
        try:
            report = json.loads(_read(self.root / "status.json"))
            # A persisted success is never proof of a running process.
            if report.get("status") == "ready" and not self._running():
                return {"status": "stopped"}
            return {
                k: report[k] for k in ("status", "error_code", "version", "endpoint") if k in report
            }
        except FileNotFoundError:
            return {"status": "not_started"}

    def _running(self):
        try:
            fd = os.open(self.root / "runtime.lock", os.O_RDWR | os.O_NOFOLLOW)
        except FileNotFoundError:
            return False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return False
            except BlockingIOError:
                return True
        finally:
            os.close(fd)

    def _report(self, status, **data):
        _write(
            self.root / "status.json",
            json.dumps({"status": status, "version": VERSION, **data}).encode(),
        )

    def ensure(self):
        with self.guard:
            _private_dir(self.root)
            if self.thread and self.thread.is_alive():
                return self.status()
            fd = os.open(self.root / "runtime.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_mode & 0o077
            ):
                os.close(fd)
                raise RuntimeError("unsafe_runtime_storage")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                return self.status()
            self.lock = fd
            self.stop_event.clear()
            _write(self.root / "enabled", b"1")
            self._report("installing")
            self.thread = threading.Thread(target=self._run, name="sam-mesh-local", daemon=True)
            self.thread.start()
            return self.status()

    def _binaries(self):
        if platform.system() != "Linux" or platform.machine() not in ARCHIVES:
            raise RuntimeError("managed_linux_required")
        arch, digest = ARCHIVES[platform.machine()]
        target = _private_dir(_private_dir(self.root / "bin") / VERSION)
        receipt = target / "verified.json"
        try:
            hashes = BINARY_HASHES[arch]
            if all(
                (target / name).is_file()
                and not (target / name).is_symlink()
                and hashlib.sha256((target / name).read_bytes()).hexdigest() == hashes[name]
                for name in ("sam-one", "sam-node")
            ):
                return target
        except (OSError, ValueError, KeyError):
            pass
        with tempfile.TemporaryFile() as archive:
            if self.archive_source:
                source = open(self.archive_source, "rb")
            else:
                request = urllib.request.Request(
                    f"https://github.com/google/sam/releases/download/{VERSION}/sam_Linux_{arch}.tar.gz",
                    headers={"User-Agent": "SAM-Mesh-Agent-Zero"},
                )
                source = urllib.request.urlopen(request, timeout=20)
            sha = hashlib.sha256()
            size = 0
            with source:
                while chunk := source.read(1024 * 1024):
                    if not self._wanted():
                        raise RuntimeError("setup_cancelled")
                    size += len(chunk)
                    if size > 160 * 1024 * 1024:
                        raise RuntimeError("download_too_large")
                    sha.update(chunk)
                    archive.write(chunk)
            if sha.hexdigest() != digest:
                raise RuntimeError("download_checksum_failed")
            archive.seek(0)
            hashes = {}
            with tarfile.open(fileobj=archive, mode="r:gz") as bundle:
                for name in ("sam-one", "sam-node"):
                    member = bundle.getmember(name)
                    if not member.isfile() or member.size > 100 * 1024 * 1024:
                        raise RuntimeError("invalid_binary_archive")
                    data = bundle.extractfile(member).read()
                    if hashlib.sha256(data).hexdigest() != BINARY_HASHES[arch][name]:
                        raise RuntimeError("download_checksum_failed")
                    _write(target / name, data)
                    (target / name).chmod(0o700)
                    hashes[name] = hashlib.sha256(data).hexdigest()
            _write(receipt, json.dumps(hashes).encode())
        return target

    def _wanted(self):
        return not self.stop_event.is_set() and (self.root / "enabled").exists()

    def _start(self, name, args):
        path = self.root / (name + ".log")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(fd, "wb") as log:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_mode & 0o077
            ):
                raise RuntimeError("unsafe_runtime_storage")
            os.ftruncate(fd, 0)
            process = subprocess.Popen(
                args,
                cwd=self.root,
                env={"PATH": os.defpath, "HOME": str(self.root), "LANG": "C.UTF-8"},
                stdout=log,
                stderr=subprocess.STDOUT,
                close_fds=True,
            )
        self.children.append(process)
        return process

    def _wait(self, condition, timeout=30):
        until = time.monotonic() + timeout
        while self._wanted() and time.monotonic() < until:
            if any(p.poll() is not None for p in self.children):
                raise RuntimeError("node_start_failed")
            if condition():
                return
            self.stop_event.wait(0.2)
        raise RuntimeError("setup_timeout" if self._wanted() else "setup_cancelled")

    def _run(self):
        try:
            binaries = self._binaries()
            self._report("starting")
            hub = _private_dir(self.root / "hub")
            node = _private_dir(self.root / "node")
            token_file = self.root / "api-token"
            if not token_file.exists():
                _write(token_file, secrets.token_urlsafe(32).encode())
            token = _read(token_file).decode().strip()
            ports_file = self.root / "ports.json"
            if not ports_file.exists():
                hub_port, node_port = _port(), _port()
                while node_port == hub_port:
                    node_port = _port()
                _write(ports_file, json.dumps([hub_port, node_port]).encode())
            hub_port, node_port = json.loads(_read(ports_file))
            if any(type(p) is not int or not 1024 <= p <= 65535 for p in (hub_port, node_port)):
                raise RuntimeError("unsafe_runtime_storage")
            config_file = self.root / "node.yaml"
            try:
                _read(config_file)
            except FileNotFoundError:
                _write(config_file, b"version: v1alpha1\nservices: []\n")
            self._start(
                "hub",
                [
                    str(binaries / "sam-one"),
                    "--bind-address",
                    "127.0.0.1",
                    "--port",
                    str(hub_port),
                    "--data-dir",
                    str(hub),
                ],
            )
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

            def hub_ready():
                if not (hub / "join-token").is_file():
                    return False
                try:
                    with opener.open(f"http://127.0.0.1:{hub_port}/info", timeout=1) as response:
                        return response.status == 200
                except OSError:
                    return False

            self._wait(hub_ready)
            self._start(
                "node",
                [
                    str(binaries / "sam-node"),
                    "run",
                    "--control-plane",
                    f"http://127.0.0.1:{hub_port}",
                    "--bootstrap-token-path",
                    str(hub / "join-token"),
                    "--api-token-path",
                    str(token_file),
                    "--data-dir",
                    str(node),
                    "--bind-addr",
                    f"127.0.0.1:{node_port}",
                    "--socket-path",
                    "",
                    "--allow-loopback",
                    "--announce-private=false",
                    "--listen",
                    "/ip4/127.0.0.1/tcp/0",
                    "--config",
                    str(self.root / "node.yaml"),
                ],
            )
            endpoint = f"http://127.0.0.1:{node_port}"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

            def ready():
                try:
                    request = urllib.request.Request(
                        endpoint + "/v1/models", headers={"Authorization": "Bearer " + token}
                    )
                    with opener.open(request, timeout=1) as response:
                        data = json.load(response)
                    return isinstance(data, dict) and isinstance(data.get("data"), list)
                except (OSError, ValueError):
                    return False

            self._wait(ready)
            self._report("ready", endpoint=endpoint)
            while self._wanted():
                if any(p.poll() is not None for p in self.children):
                    raise RuntimeError("node_stopped")
                self.stop_event.wait(1)
        except Exception as exc:
            safe = {
                "managed_linux_required",
                "download_checksum_failed",
                "download_too_large",
                "invalid_binary_archive",
                "node_start_failed",
                "setup_timeout",
                "node_stopped",
                "unsafe_runtime_storage",
            }
            self._report(
                "failed", error_code=str(exc) if str(exc) in safe else "local_setup_failed"
            )
        finally:
            for child in reversed(self.children):
                if child.poll() is None:
                    child.terminate()
            for child in reversed(self.children):
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
            self.children.clear()
            if not self._wanted():
                self._report("stopped")
            if self.lock is not None:
                os.close(self.lock)
                self.lock = None

    def close(self):
        self.stop_event.set()
        if self.thread and self.thread.is_alive() and self.thread is not threading.current_thread():
            self.thread.join(timeout=15)

    def stop(self):
        try:
            (self.root / "enabled").unlink()
        except FileNotFoundError:
            pass
        self.close()
        until = time.monotonic() + 15
        while self._running() and time.monotonic() < until:
            time.sleep(0.1)
        return {
            "status": "stopped" if not self._running() else "stopping",
            "identity_preserved": True,
        }

    def transport(self):
        status = self.ensure()
        if status.get("status") != "ready":
            raise RuntimeError("managed_mesh_starting")
        return {
            "type": "http",
            "base_url": status["endpoint"],
            "socket_path": "",
            "token_file": str(self.root / "api-token"),
            "token_secret_name": "",
            "allowed_origins": [],
        }


_manager = None
_manager_lock = threading.Lock()


def manager():
    global _manager
    with _manager_lock:
        if _manager is None:
            from helpers.files import get_abs_path

            _manager = ManagedNode(get_abs_path("usr", "sam_mesh", "managed"))
        return _manager
