#!/usr/bin/env python3
"""TCP-only adapter and fail-closed lifetime supervisor for published sam-box.

JWT parsing here can only shorten lifetime. sam-box independently verifies its
signature, operator-selected issuer, audience and subject before its socket exists.
"""

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import math
import os
import re
import signal
import stat
import time
from pathlib import Path

import yaml

MAX_CONNECTIONS = 64
MAX_SESSION_SECONDS = 300
EXPIRY_MARGIN = 30
HOST = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


def validate_names(names):
    if not isinstance(names, list) or len(names) > 128:
        raise ValueError("egress allow must be a bounded list")
    result = set()
    for host in names:
        if not isinstance(host, str) or not HOST.fullmatch(host) or host.endswith(".sam.alt"):
            raise ValueError("only exact lower-case external DNS names are accepted")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            result.add(host)
        else:
            raise ValueError("literal addresses are forbidden")
    return result


MESH_HOST = re.compile(r"(?=.{1,253}$)(?:[a-z0-9_][a-z0-9_-]*\.)+(?:mcp|inference|a2a)\.sam\.alt\Z")


def connect_target(request, allowed):
    if len(request) > 8192 or not request.endswith(b"\r\n\r\n"):
        raise ValueError("invalid header framing")
    lines = request.decode("ascii").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[0] != "CONNECT" or parts[2] != "HTTP/1.1":
        raise ValueError("only TCP CONNECT is accepted")
    target = parts[1]
    host, separator, port = target.rpartition(":")
    if (
        not separator
        or not (HOST.fullmatch(host) or MESH_HOST.fullmatch(host))
        or not port.isdecimal()
    ):
        raise ValueError("only named TCP destinations are accepted")
    if not 1 <= int(port) <= 65535 or int(port) == 53:
        raise ValueError("DNS transport is forbidden")
    if host not in allowed and host != "mesh.sam.alt" and not host.endswith(".sam.alt"):
        raise ValueError("destination is not allowed")
    for line in lines[1:-2]:
        key, sep, value = line.partition(":")
        if not sep or (key.lower(), value.strip()) not in {
            ("host", target),
            ("user-agent", "Go-http-client/1.1"),
        }:
            raise ValueError("CONNECT headers must match the published bounded wire contract")
    return target


def credential_deadline(path, now=None):
    raw = Path(path).read_bytes()
    if len(raw) > 32768:
        raise ValueError("credential is too large")
    segments = raw.strip().split(b".")
    if len(segments) != 3:
        raise ValueError("credential is not a JWT")
    claims = json.loads(base64.urlsafe_b64decode(segments[1] + b"=" * (-len(segments[1]) % 4)))
    expires = claims.get("exp")
    if (
        isinstance(expires, bool)
        or not isinstance(expires, (int, float))
        or not math.isfinite(expires)
    ):
        raise ValueError("finite credential expiry is required")
    deadline = expires - EXPIRY_MARGIN
    if deadline <= (time.time() if now is None else now):
        raise ValueError("credential expired or within drain margin")
    return deadline


def trusted_file(path):
    p = Path(path)
    st = p.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ValueError("operator files must be owned by runtime UID and mode 0600")
    return hashlib.sha256(p.read_bytes()).hexdigest()


def socket_identity(path):
    p = Path(path)
    st = p.lstat()
    parent = p.parent.lstat()
    if (
        not stat.S_ISSOCK(st.st_mode)
        or st.st_uid != os.getuid()
        or st.st_mode & 0o077
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or parent.st_mode & 0o022
    ):
        raise ValueError("socket ownership or permissions changed")
    return st.st_dev, st.st_ino


async def copy_stream(reader, writer):
    while data := await reader.read(65536):
        writer.write(data)
        await writer.drain()


async def relay(ar, aw, br, bw):
    tasks = [asyncio.create_task(copy_stream(ar, bw)), asyncio.create_task(copy_stream(br, aw))]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED, timeout=MAX_SESSION_SECONDS)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        aw.close()
        bw.close()


async def run(args):
    bundle_hash = trusted_file(args.bundle)
    bundle = yaml.safe_load(Path(args.bundle).read_text())
    if set(bundle) - {"version", "agent", "egress"} or bundle.get("version") != "v1":
        raise ValueError("this egress profile refuses ingress and unknown bundle fields")
    allowed = validate_names(bundle.get("egress", {}).get("allow", []))
    credential = bundle["agent"]["credential"]
    credential_hash = trusted_file(credential)
    deadline = credential_deadline(credential)
    node_identity = socket_identity(args.node_socket)
    # An unenrolled node exposes enrollment tools over MCP. Never expose that
    # surface to the guest; an enrolled node has the inference catalog route.
    async with asyncio.timeout(5):
        node_reader, node_writer = await asyncio.open_unix_connection(args.node_socket)
        try:
            node_writer.write(
                b"GET /v1/models HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            await node_writer.drain()
            response = await node_reader.readline()
            if response.split()[1:2] != [b"200"]:
                raise ValueError("operator must enroll the node before enabling Sovereign")
        finally:
            node_writer.close()

    public = Path(args.socket)
    public.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(public.parent, 0o700)
    private = Path(args.private_socket)
    private.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(private.parent, 0o700)
    for path in (public, private):
        if path.exists():
            if not stat.S_ISSOCK(path.lstat().st_mode):
                raise ValueError("refusing to replace a non-socket")
            path.unlink()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    process = await asyncio.create_subprocess_exec(
        args.sam_box,
        "run",
        "--socket",
        str(private),
        "--sidecar-socket",
        args.node_socket,
        "--bundle",
        args.bundle,
        "--credential-issuer",
        args.issuer,
        "--credential-audience",
        args.audience,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    active = set()
    server = None
    try:
        for _ in range(150):
            if process.returncode is not None:
                raise ValueError("sam-box credential verification or startup failed")
            if private.exists():
                break
            await asyncio.sleep(0.1)
        else:
            raise ValueError("sam-box startup exceeded 15 seconds")
        private_identity = socket_identity(private)

        async def accept(reader, writer):
            task = asyncio.current_task()
            if len(active) >= MAX_CONNECTIONS or stop.is_set():
                writer.close()
                return
            active.add(task)
            upstream_writer = None
            try:
                async with asyncio.timeout(10):
                    request = await reader.readuntil(b"\r\n\r\n")
                    target = connect_target(request, allowed)
                    upstream_reader, upstream_writer = await asyncio.open_unix_connection(private)
                    upstream_writer.write(
                        ("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n").encode()
                    )
                    await upstream_writer.drain()
                await relay(reader, writer, upstream_reader, upstream_writer)
            except (
                ValueError,
                UnicodeError,
                OSError,
                TimeoutError,
                asyncio.IncompleteReadError,
                asyncio.LimitOverrunError,
            ):
                writer.write(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            finally:
                active.discard(task)
                writer.close()
                if upstream_writer is not None:
                    upstream_writer.close()

        server = await asyncio.start_unix_server(accept, path=public, limit=8192)
        os.chmod(public, 0o600)
        public_identity = socket_identity(public)
        print("Sovereign boundary ready; verified credential; TCP-only named egress", flush=True)
        monotonic_deadline = time.monotonic() + max(0, deadline - time.time())
        while not stop.is_set():
            if (
                time.time() >= deadline
                or time.monotonic() >= monotonic_deadline
                or process.returncode is not None
                or trusted_file(args.bundle) != bundle_hash
                or trusted_file(credential) != credential_hash
                or socket_identity(public) != public_identity
                or socket_identity(private) != private_identity
                or socket_identity(args.node_socket) != node_identity
            ):
                raise ValueError("boundary drained: expiry, restart, or protected state changed")
            try:
                await asyncio.wait_for(stop.wait(), timeout=0.2)
            except TimeoutError:
                pass
    finally:
        if server:
            server.close()
        for task in list(active):
            task.cancel()
        await asyncio.gather(*active, return_exceptions=True)
        if server:
            try:
                await asyncio.wait_for(server.wait_closed(), 2)
            except TimeoutError:
                pass  # Continue mandatory child termination even if a close stalls.
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 5)
            except TimeoutError:
                process.kill()
                await process.wait()
        for path in (public, private):
            path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    for flag in ("bundle", "issuer", "audience", "node-socket", "socket"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--sam-box", default="/opt/sam/sam-box")
    parser.add_argument("--private-socket", default="/run/private/box.sock")
    args = parser.parse_args()
    try:
        asyncio.run(run(args))
    except (ValueError, OSError, KeyError, TypeError):
        print(
            "Sovereign boundary unavailable: protected configuration, credential, or runtime check failed",
            flush=True,
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
