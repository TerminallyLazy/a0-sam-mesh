"""End-to-end request attribution from the isolated SAM ingress forwarder.

Only the forwarder holds the signing key. Agent Zero verifies with a public
key, so reading its plugin files cannot mint another caller's identity.
"""

import asyncio
import base64
import hashlib
import json
import re
import secrets
import time
from collections import OrderedDict

from .decisions import DecisionError
from .embassy_sessions import VerifiedOrigin

PROOF_HEADER = "x-sam-embassy-proof"
CHALLENGE_PATH = "/__embassy_challenge"
BODY_TIMEOUT = 10
MAX_BODY = 1048576 + 16384
_PEER = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,128}$")


def _encode(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _decode(value):
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def _claims(peer, service, method, path, body, timestamp, nonce, audience):
    return {
        "v": 1,
        "audience": audience,
        "peer": peer,
        "service": service,
        "method": method,
        "path": path,
        "body": hashlib.sha256(body).hexdigest(),
        "at": timestamp,
        "nonce": nonce,
    }


class OriginSigner:
    def __init__(self, private_key, *, clock=time.time):
        self.key, self.clock = private_key, clock

    def sign(self, peer, service, method, path, body, *, audience):
        if type(audience) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{43}", audience):
            raise DecisionError("origin_invalid")
        if peer and not _PEER.fullmatch(peer):
            raise DecisionError("origin_invalid")
        claims = _claims(
            peer,
            service,
            method,
            path,
            body,
            int(self.clock()),
            secrets.token_urlsafe(24),
            audience,
        )
        payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        return _encode(payload) + "." + _encode(self.key.sign(payload))


class OriginVerifier:
    def __init__(self, public_key, *, clock=time.time, capacity=10000):
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        self.key, self.clock, self.capacity = public_key, clock, capacity
        self.boundary = hashlib.sha256(
            public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).hexdigest()
        self.seen = OrderedDict()
        self.challenge = secrets.token_urlsafe(32)

    def verify(self, proof, service, method, path, body):
        try:
            if type(proof) is not str or not 1 <= len(proof) <= 8192:
                raise ValueError()
            encoded, signature = proof.split(".")
            payload = _decode(encoded)
            self.key.verify(_decode(signature), payload)
            claims = json.loads(payload)
            if (
                type(claims) is not dict
                or type(claims.get("at")) is not int
                or type(claims.get("peer")) is not str
                or (claims["peer"] and not _PEER.fullmatch(claims["peer"]))
                or type(claims.get("nonce")) is not str
                or not re.fullmatch(r"[A-Za-z0-9_-]{32}", claims["nonce"])
                or claims
                != _claims(
                    claims["peer"],
                    service,
                    method,
                    path,
                    body,
                    claims["at"],
                    claims["nonce"],
                    self.challenge,
                )
            ):
                raise ValueError()
        except Exception:
            raise DecisionError("origin_invalid") from None
        now = self.clock()
        if not -5 <= now - claims["at"] <= 30:
            raise DecisionError("origin_expired")
        for nonce, expiry in list(self.seen.items()):
            if expiry < now:
                del self.seen[nonce]
        nonce = claims["nonce"]
        if nonce in self.seen:
            raise DecisionError("origin_replay")
        if len(self.seen) >= self.capacity:
            raise DecisionError("origin_capacity")
        self.seen[nonce] = claims["at"] + 30
        return VerifiedOrigin(claims["peer"], self.boundary) if claims["peer"] else None


class OriginMiddleware:
    """Verify before handing any request to FastMCP; replay body exactly once."""

    def __init__(self, app, service, verifier):
        self.app, self.service, self.verifier = app, service, verifier

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        try:
            if scope.get("query_string"):
                raise DecisionError("origin_invalid")
            proofs = [v for k, v in scope.get("headers", []) if k.lower() == PROOF_HEADER.encode()]
            if len(proofs) != 1:
                raise DecisionError("origin_invalid")
            chunks, length = [], 0
            async with asyncio.timeout(BODY_TIMEOUT):
                while True:
                    message = await receive()
                    if message["type"] != "http.request":
                        raise DecisionError("origin_invalid")
                    body = message.get("body", b"")
                    length += len(body)
                    if length > MAX_BODY:
                        raise DecisionError("input_too_large")
                    chunks.append(body)
                    if not message.get("more_body"):
                        break
            body = b"".join(chunks)
            origin = self.verifier.verify(
                proofs[0].decode("ascii"), self.service, scope["method"], scope["path"], body
            )
            if origin is None:
                # SAM probes and catalogs initialize/list without a remote peer.
                # No anonymous tool call, resource or prompt request is accepted.
                value = json.loads(body)
                if type(value) is not dict or value.get("method") not in {
                    "initialize",
                    "notifications/initialized",
                    "tools/list",
                    "ping",
                }:
                    raise DecisionError("verified_origin_required")
            scope = dict(scope, sam_verified_origin=origin)
        except Exception:
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send(
                {"type": "http.response.body", "body": b'{"error":"verified_origin_required"}'}
            )
            return

        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
