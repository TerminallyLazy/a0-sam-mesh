"""Published TUN DNS is accepted only inside the certified mesh facade."""

import socket
import unittest
from unittest.mock import patch

from helpers.domain import TransportConfig
from helpers.mcp_transport import SamConnectivityError, validate_tcp_origin


def config(base="http://mesh.sam.alt", token=None):
    return TransportConfig(
        type="http", base_url=base, socket_path=None, token=token, allowed_origins=(base,)
    )


def answers(*addresses):
    async def resolve(*args):
        return [
            (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 80))
            for ip in addresses
        ]

    return resolve


class SovereignTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_published_dual_stack_dns_requires_observed_guest(self):
        with patch("helpers.sovereign.guest_probe", return_value={"supported": True}) as probe:
            self.assertEqual(
                await validate_tcp_origin(config(), resolver=answers("100.64.0.1", "100::1")),
                ("100.64.0.1", "100::1"),
            )
        probe.assert_called_once_with()

    async def test_synthetic_mesh_dns_denied_without_certified_guest(self):
        for addresses in [("100.64.0.1",), ("100::1",), ("100.64.0.1", "100::1")]:
            with self.subTest(addresses=addresses):
                with patch("helpers.sovereign.guest_probe", return_value={"supported": False}):
                    with self.assertRaises(SamConnectivityError):
                        await validate_tcp_origin(config(), resolver=answers(*addresses))

    async def test_certified_guest_rejects_every_non_synthetic_answer(self):
        for address in [
            "127.0.0.1",
            "169.254.169.254",
            "8.8.8.8",
            "2001:4860:4860::8888",
            "101::1",
        ]:
            with self.subTest(address=address):
                with patch("helpers.sovereign.guest_probe", return_value={"supported": True}):
                    with self.assertRaises(SamConnectivityError):
                        await validate_tcp_origin(config(), resolver=answers("100.64.0.1", address))

    async def test_exception_cannot_extend_to_other_origins_or_credentials(self):
        for transport in [
            config("http://other.sam.alt"),
            config("https://mesh.sam.alt"),
            config("http://mesh.sam.alt:8080"),
            config("http://mesh.sam.alt/v1"),
            config(token="fixture-credential"),
        ]:
            with self.subTest(base=transport.base_url, token=bool(transport.token)):
                with patch("helpers.sovereign.guest_probe", return_value={"supported": True}):
                    with self.assertRaises(SamConnectivityError):
                        await validate_tcp_origin(transport, resolver=answers("100::1"))
