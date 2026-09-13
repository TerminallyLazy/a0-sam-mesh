"""Only the isolated SAM HTTP ingress may attest a peer to the broker."""

import json
import unittest

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class EmbassyGatewayTests(unittest.IsolatedAsyncioTestCase):
    async def test_signed_forwarding_and_unattributed_call_denial(self):
        from helpers.embassy_gateway import EmbassyGateway
        from helpers.embassy_origin import OriginVerifier

        key = Ed25519PrivateKey.generate()
        verifier = OriginVerifier(key.public_key())
        received = []

        async def backend(request):
            if request.method == "GET":
                self.assertEqual(str(request.url), "http://embassy.invalid/__embassy_challenge")
                self.assertNotIn("authorization", request.headers)
                return httpx.Response(200, json={"challenge": verifier.challenge})
            origin = verifier.verify(
                request.headers["x-sam-embassy-proof"],
                "research-desk",
                request.method,
                request.url.path,
                request.content,
            )
            received.append(origin.peer_id if origin else None)
            self.assertNotIn("authorization", request.headers)
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

        upstream = httpx.AsyncClient(transport=httpx.MockTransport(backend))
        gateway = EmbassyGateway(key, upstream)
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway, client=("127.0.0.1", 42000)),
            base_url="http://localhost",
        )
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "service_info"}}
        )
        peer = "12D3KooW" + "A" * 44
        try:
            response = await client.post(
                "/research-desk/mcp",
                content=body,
                headers={
                    "x-peer-id": peer,
                    "authorization": "never-forward",
                    "x-sam-embassy-proof": "forged",
                },
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(received, [peer])
            response = await client.post("/research-desk/mcp", content=body)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(received, [peer])
        finally:
            await client.aclose()
            await upstream.aclose()

    async def test_non_loopback_source_is_refused(self):
        from helpers.embassy_gateway import EmbassyGateway

        async def backend(request):
            self.fail("non-loopback request reached broker")

        upstream = httpx.AsyncClient(transport=httpx.MockTransport(backend))
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(
                app=EmbassyGateway(Ed25519PrivateKey.generate(), upstream), client=("10.1.1.2", 2)
            ),
            base_url="http://localhost",
        )
        try:
            self.assertEqual((await client.post("/research-desk/mcp", json={})).status_code, 403)
        finally:
            await client.aclose()
            await upstream.aclose()

    async def test_challenge_is_fixed_bounded_and_restart_race_never_retries_call(self):
        from helpers.embassy_gateway import EmbassyGateway
        from helpers.embassy_origin import OriginVerifier

        key = Ed25519PrivateKey.generate()
        old, restarted = OriginVerifier(key.public_key()), OriginVerifier(key.public_key())
        requests = []
        mode = "race"

        async def backend(request):
            requests.append((request.method, str(request.url)))
            self.assertNotIn("x-sam-embassy-audience", request.headers)
            if request.method == "GET":
                if mode == "huge":
                    return httpx.Response(200, content=b"x" * 129)
                return httpx.Response(200, json={"challenge": old.challenge})
            with self.assertRaisesRegex(Exception, "origin_invalid"):
                restarted.verify(
                    request.headers["x-sam-embassy-proof"],
                    "research-desk",
                    "POST",
                    "/research-desk/mcp",
                    request.content,
                )
            return httpx.Response(401)

        async with httpx.AsyncClient(transport=httpx.MockTransport(backend)) as upstream:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(
                    app=EmbassyGateway(key, upstream), client=("127.0.0.1", 1)
                ),
                base_url="http://caller.invalid",
            ) as client:
                response = await client.post(
                    "/research-desk/mcp",
                    json={"method": "tools/call"},
                    headers={
                        "x-peer-id": "12D3KooW" + "A" * 44,
                        "x-sam-embassy-audience": restarted.challenge,
                    },
                )
                self.assertEqual(response.status_code, 401)
                self.assertEqual(
                    requests,
                    [
                        ("GET", "http://embassy.invalid/__embassy_challenge"),
                        ("POST", "http://embassy.invalid/research-desk/mcp"),
                    ],
                )
                mode = "huge"
                requests.clear()
                response = await client.post("/research-desk/mcp", json={"method": "tools/list"})
                self.assertEqual(response.status_code, 502)
                self.assertEqual(requests, [("GET", "http://embassy.invalid/__embassy_challenge")])
