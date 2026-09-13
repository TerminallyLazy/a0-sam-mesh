"""The last hop must authenticate the exact request and reject replay."""

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class EmbassyOriginTests(unittest.TestCase):
    def setUp(self):
        from helpers.embassy_origin import OriginSigner, OriginVerifier

        self.key = Ed25519PrivateKey.generate()
        self.now = 2000000000
        self.signer = OriginSigner(self.key, clock=lambda: self.now)
        self.verifier = OriginVerifier(self.key.public_key(), clock=lambda: self.now)
        self.peer = "12D3KooW" + "A" * 44
        self.args = ("research-desk", "POST", "/research-desk/mcp", b'{"id":1}')

    def test_exact_signed_origin_and_replay(self):
        proof = self.signer.sign(self.peer, *self.args, audience=self.verifier.challenge)
        origin = self.verifier.verify(proof, *self.args)
        self.assertEqual(origin.peer_id, self.peer)
        with self.assertRaisesRegex(Exception, "origin_replay"):
            self.verifier.verify(proof, *self.args)

    def test_tampered_request_service_and_key_are_rejected(self):
        from helpers.embassy_origin import OriginSigner

        for position, changed in [(0, "other-desk"), (1, "GET"), (2, "/other"), (3, b"stolen")]:
            args = list(self.args)
            args[position] = changed
            with self.assertRaisesRegex(Exception, "origin_invalid"):
                self.verifier.verify(
                    self.signer.sign(self.peer, *self.args, audience=self.verifier.challenge), *args
                )
        wrong = OriginSigner(Ed25519PrivateKey.generate(), clock=lambda: self.now)
        with self.assertRaisesRegex(Exception, "origin_invalid"):
            self.verifier.verify(
                wrong.sign(self.peer, *self.args, audience=self.verifier.challenge), *self.args
            )

    def test_expiry_future_and_missing_proof_fail_closed(self):
        proof = self.signer.sign(self.peer, *self.args, audience=self.verifier.challenge)
        self.now += 31
        with self.assertRaisesRegex(Exception, "origin_expired"):
            self.verifier.verify(proof, *self.args)
        self.now -= 60
        with self.assertRaisesRegex(Exception, "origin_expired"):
            self.verifier.verify(proof, *self.args)
        for value in (None, "", "x" * 8193, "broken.signature"):
            with self.assertRaises(Exception):
                self.verifier.verify(value, *self.args)

    def test_probe_does_not_become_a_verified_caller(self):
        proof = self.signer.sign("", *self.args, audience=self.verifier.challenge)
        self.assertIsNone(self.verifier.verify(proof, *self.args))

    def test_capacity_denies_without_evicting_live_replay_records(self):
        self.verifier.capacity = 1
        first = self.signer.sign(self.peer, *self.args, audience=self.verifier.challenge)
        self.verifier.verify(first, *self.args)
        with self.assertRaisesRegex(Exception, "origin_capacity"):
            self.verifier.verify(
                self.signer.sign(self.peer, *self.args, audience=self.verifier.challenge),
                *self.args,
            )
        with self.assertRaisesRegex(Exception, "origin_replay"):
            self.verifier.verify(first, *self.args)

    def test_consumed_proof_rejected_after_receiver_restart(self):
        from helpers.embassy_origin import OriginVerifier

        proof = self.signer.sign(self.peer, *self.args, audience=self.verifier.challenge)
        self.verifier.verify(proof, *self.args)
        restarted = OriginVerifier(self.key.public_key(), clock=lambda: self.now)
        with self.assertRaisesRegex(Exception, "origin_invalid"):
            restarted.verify(proof, *self.args)

    def test_caller_chosen_or_missing_audience_is_rejected(self):
        import base64
        import json

        proof = self.signer.sign(self.peer, *self.args, audience="A" * 43)
        with self.assertRaisesRegex(Exception, "origin_invalid"):
            self.verifier.verify(proof, *self.args)
        payload = json.loads(base64.urlsafe_b64decode(proof.split(".")[0] + "=="))
        del payload["audience"]
        raw = json.dumps(payload).encode()

        def encode(value):
            return base64.urlsafe_b64encode(value).decode().rstrip("=")

        legacy = encode(raw) + "." + encode(self.key.sign(raw))
        with self.assertRaisesRegex(Exception, "origin_invalid"):
            self.verifier.verify(legacy, *self.args)


class OriginMiddlewareTests(unittest.IsolatedAsyncioTestCase):
    async def test_unsigned_rejected_before_read_and_signed_slow_body_times_out(self):
        import asyncio
        from unittest.mock import patch

        from helpers.embassy_origin import OriginMiddleware, OriginVerifier

        async def app(*args):
            self.fail("invalid body reached application")

        async def slow():
            await asyncio.Event().wait()

        verifier = OriginVerifier(Ed25519PrivateKey.generate().public_key())
        middleware = OriginMiddleware(app, "research-desk", verifier)
        scope = {"type": "http", "method": "POST", "path": "/research-desk/mcp", "headers": []}
        sent = []

        async def send(value):
            sent.append(value)

        await asyncio.wait_for(middleware(scope, slow, send), 0.1)
        self.assertEqual(sent[0]["status"], 401)
        scope["headers"] = [(b"x-sam-embassy-proof", b"present")]
        sent.clear()
        with patch("helpers.embassy_origin.BODY_TIMEOUT", 0.01):
            await asyncio.wait_for(middleware(scope, slow, send), 0.1)
        self.assertEqual(sent[0]["status"], 401)

    async def test_oversized_stream_stops_reading_at_bound(self):
        from helpers.embassy_origin import MAX_BODY, OriginMiddleware, OriginVerifier

        calls = 0

        async def receive():
            nonlocal calls
            calls += 1
            self.assertLess(calls, 3)
            return {"type": "http.request", "body": b"x" * (MAX_BODY // 2 + 1), "more_body": True}

        async def app(*args):
            self.fail("oversized request reached application")

        sent = []

        async def send(value):
            sent.append(value)

        middleware = OriginMiddleware(
            app, "research-desk", OriginVerifier(Ed25519PrivateKey.generate().public_key())
        )
        await middleware(
            {"type": "http", "headers": [(b"x-sam-embassy-proof", b"present")]}, receive, send
        )
        self.assertEqual(sent[0]["status"], 401)
        self.assertEqual(calls, 2)

    async def test_concurrent_delivery_consumes_proof_once(self):
        import asyncio

        from helpers.embassy_origin import OriginSigner, OriginVerifier

        key = Ed25519PrivateKey.generate()
        verifier = OriginVerifier(key.public_key())
        args = ("research-desk", "POST", "/research-desk/mcp", b'{"method":"tools/call"}')
        proof = OriginSigner(key).sign("12D3KooW" + "A" * 44, *args, audience=verifier.challenge)

        async def deliver():
            return verifier.verify(proof, *args)

        results = await asyncio.gather(deliver(), deliver(), return_exceptions=True)
        self.assertEqual(sum(not isinstance(result, Exception) for result in results), 1)
        self.assertEqual(
            [str(result) for result in results if isinstance(result, Exception)], ["origin_replay"]
        )
