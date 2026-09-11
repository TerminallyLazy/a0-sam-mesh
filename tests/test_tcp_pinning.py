"""Connection-time authority must precede the first credential byte."""

import unittest
from unittest.mock import AsyncMock, patch

from helpers.domain import TransportConfig
from tests.fakes.sam_sidecar import FakeSamSidecar


class TcpPinningTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_tcp_health_and_mcp(self):
        from helpers.sam_client import SamClient

        async with FakeSamSidecar() as node:
            config = TransportConfig(
                type="http", base_url=node.base_url, socket_path=None, token="local-test"
            )
            async with SamClient(config) as client:
                self.assertTrue((await client.health()).ready)
                self.assertTrue(await client.list_tools())

    async def test_connect_uses_validated_literal_and_verifies_peer(self):
        from helpers.tcp_transport import PinnedTcpBackend

        config = TransportConfig(
            type="http",
            base_url="https://node.example",
            socket_path=None,
            token=None,
            allowed_origins=("https://node.example",),
        )
        stream = AsyncMock()
        stream.get_extra_info = lambda key: ("192.0.2.8", 443)
        with (
            patch(
                "helpers.mcp_transport.validate_tcp_origin", AsyncMock(return_value=("192.0.2.8",))
            ),
            patch(
                "httpcore._backends.anyio.AnyIOBackend.connect_tcp", AsyncMock(return_value=stream)
            ) as connect,
        ):
            backend = PinnedTcpBackend(config)
            self.assertIs(await backend.connect_tcp("node.example", 443), stream)
            self.assertEqual(connect.call_args.args[0], "192.0.2.8")
            with self.assertRaises(Exception):
                await backend.connect_tcp("attacker.example", 443)
            self.assertEqual(connect.await_count, 1)

    async def test_wrong_connected_peer_is_closed_before_use(self):
        from helpers.tcp_transport import PinnedTcpBackend

        config = TransportConfig(
            type="http", base_url="http://127.0.0.1:8080", socket_path=None, token=None
        )
        stream = AsyncMock()
        stream.get_extra_info = lambda key: ("169.254.169.254", 8080)
        with (
            patch(
                "helpers.mcp_transport.validate_tcp_origin", AsyncMock(return_value=("127.0.0.1",))
            ),
            patch(
                "httpcore._backends.anyio.AnyIOBackend.connect_tcp", AsyncMock(return_value=stream)
            ),
        ):
            with self.assertRaises(Exception):
                await PinnedTcpBackend(config).connect_tcp("127.0.0.1", 8080)
            stream.aclose.assert_awaited_once()
