"""Native provider and route disclosure contracts."""

import unittest
from dataclasses import replace
from pathlib import Path

import yaml

from tests.test_gate import GateTests


class ProviderTests(unittest.TestCase):
    def test_provider_has_no_credential_or_responses_mode(self):
        value = yaml.safe_load(
            (Path(__file__).parents[1] / "conf/model_providers.yaml").read_text()
        )
        cfg = value["chat"]["sam_mesh"]
        self.assertEqual(cfg["litellm_provider"], "openai")
        self.assertEqual(cfg["kwargs"]["a0_api_mode"], "chat")
        self.assertEqual(cfg["models_list"]["endpoint_url"], "/models")
        self.assertNotIn("api_key", cfg["kwargs"])


class RouteTests(GateTests):
    async def test_automatic_route_is_not_exact_disclosure(self):
        from helpers.inference import preview_route

        route = preview_route(self.config, {"mode": "automatic", "model": "test"})
        self.assertFalse(route["exact_recipient"])
        self.assertTrue(route["may_fail_over"])
        self.assertFalse(route["enabled"])

    async def test_pinned_route_cannot_accept_an_arbitrary_url(self):
        from helpers.inference import preview_route

        with self.assertRaises(Exception):
            preview_route(
                self.config,
                {"mode": "pinned", "model": "test", "proxy_root": "http://attacker.example"},
            )

    async def test_preset_requires_inference_and_http(self):
        from helpers.inference import build_preset_fragment

        with self.assertRaises(Exception):
            build_preset_fragment(self.config, "test")
        cfg = replace(
            self.config,
            features=replace(self.config.features, mesh_inference=True),
            passport=replace(
                self.config.passport,
                inference=replace(self.config.passport.inference, enabled=True),
            ),
            transport=replace(self.config.transport, type="http", base_url="http://127.0.0.1:8080"),
        )
        fragment = build_preset_fragment(cfg, "test")
        self.assertEqual(fragment["api_base"], "http://127.0.0.1:8080/v1")
        self.assertNotIn("token", str(fragment))


class InferenceWireTests(unittest.IsolatedAsyncioTestCase):
    async def test_inference_status_taxonomy(self):
        from helpers.inference import inference_error

        for status, expected in (
            (401, "auth_required"),
            (403, "auth_rejected"),
            (404, "model_not_found"),
            (429, "rate_limited"),
            (503, "provider_exhausted"),
        ):
            self.assertEqual(inference_error(status), expected)


class NamedInferenceTests(GateTests):
    async def test_named_payload_requires_exact_single_use_approval(self):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock, patch

        from helpers.inference_gate import InferenceGate

        self.config = replace(
            self.config,
            features=replace(self.config.features, mesh_inference=True),
            passport=replace(
                self.config.passport,
                inference=replace(self.config.passport.inference, enabled=True),
            ),
        )
        send = AsyncMock(return_value=(None, [{"choices": [{"message": {"content": "ok"}}]}]))
        client = SimpleNamespace(mcp=SimpleNamespace(_send=send))
        gate = InferenceGate(lambda: self.config, client, (self.store, self.leases, self.audit))
        route = {
            "peer_id": "peerA",
            "service": "reviewer",
            "proxy_root": "http://sam.local/sam/peerA/inference/reviewer",
            "path": "/sam/peerA/inference/reviewer/chat/completions",
        }
        with patch("helpers.inference_gate.discover_route", AsyncMock(return_value=route)):
            identifier = await gate.preflight(
                "peerA", "reviewer", "model", "private text", "public"
            )
            with self.assertRaisesRegex(Exception, "approval_required"):
                await gate.invoke(identifier)
            send.assert_not_awaited()
            gate.approve(identifier, "APPROVE")
            result = await gate.invoke(identifier)
            self.assertEqual(result["status"], "verified_now")
            self.assertNotIn("Authorization", send.call_args.kwargs["headers"])
            with self.assertRaises(Exception):
                await gate.invoke(identifier)
            self.assertEqual(send.await_count, 1)
