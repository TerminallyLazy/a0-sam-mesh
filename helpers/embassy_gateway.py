"""Operator workload: sign SAM-stamped HTTP callers and forward over private UDS.

Run ONLY beside sam-node in its exclusive network namespace. Loopback alone
on a shared host is not authentication. Never mount the private key in A0.
"""

import argparse
import asyncio
import base64
import json
import os
import re
import stat
from pathlib import Path

import httpx

from .embassy_origin import CHALLENGE_PATH, MAX_BODY, PROOF_HEADER, OriginSigner
from .uds_transport import PinnedUnixTransport


class EmbassyGateway:
    def __init__(self, private_key, client):
        self.signer, self.client = OriginSigner(private_key), client

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return

        async def error(status):
            await send({"type": "http.response.start", "status": status, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        if (scope.get("client") or (None,))[0] != "127.0.0.1":
            return await error(403)
        path = scope.get("path", "")
        match = re.fullmatch(r"/([a-z][a-z0-9-]{2,62})/mcp", path)
        if not match or scope.get("query_string") or scope["method"] != "POST":
            return await error(404)
        try:
            chunks, length = [], 0
            async with asyncio.timeout(10):
                while True:
                    message = await receive()
                    if message["type"] != "http.request":
                        return await error(400)
                    body = message.get("body", b"")
                    length += len(body)
                    if length > MAX_BODY:
                        return await error(413)
                    chunks.append(body)
                    if not message.get("more_body"):
                        break
            body = b"".join(chunks)
            peers = [v for k, v in scope["headers"] if k.lower() == b"x-peer-id"]
            if len(peers) > 1:
                return await error(401)
            peer = peers[0].decode("ascii") if peers else ""
            if not peer:
                value = json.loads(body)
                if type(value) is not dict or value.get("method") not in {
                    "initialize",
                    "notifications/initialized",
                    "tools/list",
                    "ping",
                }:
                    return await error(401)
        except Exception:
            return await error(400)
        try:
            # Only the configured pinned UDS client chooses the receiving broker.
            # Never accept caller audience, URL, query, headers, or redirect targets.
            async with asyncio.timeout(3):
                async with self.client.stream(
                    "GET", "http://embassy.invalid" + CHALLENGE_PATH, follow_redirects=False
                ) as response:
                    if response.status_code != 200:
                        raise ValueError("challenge_unavailable")
                    challenge = bytearray()
                    async for chunk in response.aiter_bytes():
                        challenge.extend(chunk)
                        if len(challenge) > 128:
                            raise ValueError("challenge_too_large")
                    value = json.loads(challenge)
                    if type(value) is not dict or set(value) != {"challenge"}:
                        raise ValueError("challenge_invalid")
            proof = self.signer.sign(
                peer, match[1], "POST", path, body, audience=value["challenge"]
            )
        except Exception:
            return await error(502)
        # Do not forward any caller credential, asserted proof, cookies, proxy
        # header or MCP session handle. The broker is stateless HTTP; its own
        # specialist sessions are separately bound to verified origin/service.
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            PROOF_HEADER: proof,
        }
        started = False
        try:
            async with self.client.stream(
                "POST", "http://embassy.invalid" + path, content=body, headers=headers
            ) as response:
                await send(
                    {
                        "type": "http.response.start",
                        "status": response.status_code,
                        "headers": [
                            (
                                b"content-type",
                                response.headers.get("content-type", "application/json").encode(),
                            )
                        ],
                    }
                )
                started = True
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > 2 * MAX_BODY:
                        raise ValueError("broker_response_too_large")
                    await send({"type": "http.response.body", "body": chunk, "more_body": True})
                await send({"type": "http.response.body", "body": b""})
        except Exception:
            if not started:
                await error(502)
            else:
                await send({"type": "http.response.body", "body": b""})
            # A lost response is ambiguous. Never retry a specialist call.


def load_private_key(path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = Path(path)
    metadata = path.lstat()
    if (
        path.resolve() != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError("private_key_permissions")
    raw = path.read_bytes()
    if len(raw) > 128:
        raise ValueError("private_key_invalid")
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw.strip(), validate=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--broker-socket", required=True)
    parser.add_argument("--port", type=int, default=7081)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be unprivileged")

    async def serve():
        import uvicorn

        key = load_private_key(args.key_file)
        async with httpx.AsyncClient(
            transport=PinnedUnixTransport(args.broker_socket),
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(910, connect=3),
            limits=httpx.Limits(max_connections=16),
        ) as client:
            app = EmbassyGateway(key, client)
            server = uvicorn.Server(
                uvicorn.Config(
                    app,
                    host="127.0.0.1",
                    port=args.port,
                    lifespan="off",
                    access_log=False,
                    proxy_headers=False,
                    log_level="error",
                    limit_concurrency=32,
                    timeout_graceful_shutdown=35,
                )
            )
            await server.serve()

    asyncio.run(serve())


if __name__ == "__main__":
    main()
