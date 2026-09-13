"""Assertions executed inside the networkless agent by the Docker certifier."""

import argparse
import json
import os
import socket
import time
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("mode", choices=["network", "adapter"])
p.add_argument("--infra-ip", required=True)
a = p.parse_args()
checks = {}
diagnostics = []


def connected(host, port):
    if a.mode == "network":
        return socket.create_connection((host, port), timeout=3)
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(3)
    s.connect("/run/sam-agent/agent.sock")
    target = host + ":" + str(port)
    s.sendall(
        (
            "CONNECT "
            + target
            + " HTTP/1.1\r\nHost: "
            + target
            + "\r\nUser-Agent: Go-http-client/1.1\r\n\r\n"
        ).encode()
    )
    response = b""
    while b"\r\n\r\n" not in response:
        piece = s.recv(1)
        if not piece:
            s.close()
            raise OSError("boundary closed before admission")
        response += piece
    if not response.startswith(b"HTTP/1.1 200"):
        s.close()
        raise OSError("boundary refused")
    return s


def http(host, path, port=80, body=None):
    observation = {"host": host, "port": port, "path": path, "mode": a.mode, "stage": "connect"}
    diagnostics.append(observation)
    try:
        with connected(host, port) as s:
            observation["stage"] = "send"
            data = (
                ("POST" if body else "GET")
                + " "
                + path
                + " HTTP/1.1\r\nHost: "
                + host
                + "\r\nConnection: close\r\n"
            ).encode()
            if body:
                data += (
                    "Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: "
                    + str(len(body))
                    + "\r\n"
                ).encode()
            s.sendall(data + b"\r\n" + (body or b""))
            observation["stage"] = "receive"
            response = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                response += chunk
            status = response.split(b"\r\n", 1)[0].split()
            observation["status"] = (
                status[1].decode("ascii", errors="replace") if len(status) > 1 else "empty"
            )
            observation["bytes"] = len(response)
            observation["stage"] = "complete"
            return response
    except (OSError, TimeoutError) as exc:
        # Fixtures use public sentinels only. Never record response bodies, tokens,
        # request headers, or arbitrary exception text in certification receipts.
        observation["error"] = type(exc).__name__
        observation["errno"] = getattr(exc, "errno", None)
        raise


checks["tun_real"] = (
    set(name for _, name in socket.if_nameindex()) == {"lo", "tun0"}
    and Path("/dev/net/tun").exists()
)
checks["node_authority_absent"] = not any(
    Path(path).exists()
    for path in ["/run/sam-node", "/run/credentials", "/fixture", "/run/private"]
) and not os.environ.get("SAM_API_TOKEN")
checks["socket_separation"] = (
    checks["node_authority_absent"] and Path("/run/sam-agent/agent.sock").exists()
)
if a.mode == "network" and not checks["tun_real"]:
    print(json.dumps(dict(checks, _diagnostics=diagnostics), sort_keys=True))
    raise SystemExit(0)

for label, host, port in [
    ("unapproved_name_denied", "denied.test", 18081),
    ("literal_ip_denied", a.infra_ip, 18081),
    ("literal_ipv6_denied", "2606:4700:4700::1111", 443),
]:
    try:
        http(host, "/forbidden", port)
        checks[label] = False
    except (OSError, TimeoutError):
        checks[label] = True
try:
    checks["named_external_allowed"] = b"allowed-destination" in http(
        "allowed.test", "/allowed-proof", 18081
    )
except (OSError, TimeoutError):
    checks["named_external_allowed"] = False
try:
    checks["mesh_models_allowed"] = (
        http("mesh.sam.alt", "/v1/models").split(b"\r\n")[0].split()[1] == b"200"
    )
except (OSError, TimeoutError):
    checks["mesh_models_allowed"] = False
body = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"sovereign-cert","version":"1"}}}'
try:
    checks["mesh_mcp_allowed"] = b"200" in http("mesh.sam.alt", "/mcp", body=body).split(b"\r\n")[0]
except (OSError, TimeoutError):
    checks["mesh_mcp_allowed"] = False
checks["named_mesh_mcp_allowed"] = False
for _ in range(15):
    try:
        checks["named_mesh_mcp_allowed"] = b"sovereign-network-witness" in http(
            "sovereign_probe.mcp.sam.alt", "/mcp", body=body
        )
        if checks["named_mesh_mcp_allowed"]:
            break
    except (OSError, TimeoutError):
        pass
    time.sleep(1)
checks["mesh_admin_denied"] = True
for path in [
    "/health",
    "/sam/service/discover",
    "/sam/service/register",
    "/sam/peers",
    "/v1/models/../admin",
    "/%73am/service/register",
]:
    try:
        status = http("mesh.sam.alt", path).split(b"\r\n")[0].split()[1]
        checks["mesh_admin_denied"] &= status == b"403"
    except (OSError, TimeoutError):
        checks["mesh_admin_denied"] = False
# Virtual DNS can return synthetic replies; the external witness proves no packets left.
for host, port, data in [
    ("allowed.test", 18082, b"UDP-EXFIL"),
    (a.infra_ip, 18082, b"UDP-IP-EXFIL"),
    (
        a.infra_ip,
        53,
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08exfilcan\x04test\x00\x00\x01\x00\x01",
    ),
]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.sendto(data, (host, port))
            try:
                s.recv(1024)
            except TimeoutError:
                pass
    except OSError:
        pass
# Direct public UDS users cannot request the upstream's UDP protocol either.
with socket.socket(socket.AF_UNIX) as s:
    s.settimeout(3)
    s.connect("/run/sam-agent/agent.sock")
    s.sendall(
        b"GET /.well-known/masque/udp/allowed.test/18082/ HTTP/1.1\r\nUpgrade: connect-udp\r\n\r\n"
    )
    checks["udp_protocol_denied"] = b"403" in s.recv(1024)
print(json.dumps(dict(checks, _diagnostics=diagnostics), sort_keys=True))
