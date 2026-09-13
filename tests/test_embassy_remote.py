"""Embassy HTTP calls retain exact peer routes and never forward local auth."""

import unittest

from helpers.domain import TransportConfig
from helpers.mcp_transport import SamSchemaError
from helpers.sam_client import SamClient
from tests.fakes.sam_sidecar import FakeSamSidecar


class EmbassyRemoteTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_route_one_call_and_node_auth_header(self):
        class Sidecar(FakeSamSidecar):
            def _response(self, method, target, headers, payload):
                if target.startswith("/sam/"):
                    return self._json(
                        200,
                        {
                            "jsonrpc": "2.0",
                            "id": payload["id"],
                            "result": {"content": [{"type": "text", "text": "ok"}]},
                        },
                    )
                return super()._response(method, target, headers, payload)

        peer = "12D3KooW" + "A" * 44
        async with Sidecar() as server:
            cfg = TransportConfig("http", server.base_url, None, "node-only-credential")
            async with SamClient(cfg) as client:
                result = await client.call_embassy_tool(
                    peer, "mcp://research-desk/ask_specialist", {"message": "hello"}
                )
                self.assertEqual(result.content[0]["text"], "ok")
            self.assertEqual(len(server.received), 1)
            call = server.received[0]
            self.assertEqual(call["path"], f"/sam/{peer}/mcp/research-desk")
            self.assertEqual(
                call["headers"].get("x-sam-authentication"), "Bearer node-only-credential"
            )
            self.assertNotIn("authorization", call["headers"])
            self.assertEqual(call["json"]["params"]["name"], "ask_specialist")

    async def test_malformed_destinations_never_dispatch(self):
        async with FakeSamSidecar() as server:
            async with SamClient(TransportConfig("http", server.base_url, None, None)) as client:
                for peer, uri in [
                    ("../../other", "mcp://research-desk/service_info"),
                    ("A" * 50, "mcp://research-desk/../service_info"),
                    ("A" * 50, "mcp://evil@research-desk/service_info"),
                    ("A" * 50, "mcp://research-desk/service_info?x=y"),
                ]:
                    with self.assertRaisesRegex(SamSchemaError, "invalid_embassy_destination"):
                        await client.call_embassy_tool(peer, uri, {})
            self.assertEqual(server.received, [])
