"""Resolve, pin and verify each TCP connection before HTTP sends credentials."""

import asyncio
import ipaddress
from urllib.parse import urlsplit

import httpcore
import httpx
from httpcore._backends.anyio import AnyIOBackend


class PinnedTcpBackend(AnyIOBackend):
    def __init__(self, config, resolver=None):
        self.config = config
        self.resolver = resolver

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        from .mcp_transport import validate_tcp_origin

        parsed = urlsplit(self.config.base_url)
        expected_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if host != parsed.hostname or port != expected_port or local_address is not None:
            raise httpcore.ConnectError("tcp_origin_changed")
        stream = None
        try:
            async with asyncio.timeout(timeout):
                addresses = await validate_tcp_origin(self.config, resolver=self.resolver)
                # One connection attempt. HTTPcore retains the original host for TLS SNI
                # and certificate verification; DNS cannot replace this numeric target.
                target = addresses[0]
                stream = await super().connect_tcp(target, port, timeout, None, socket_options)
                peer = stream.get_extra_info("server_addr")
                if (
                    not peer
                    or ipaddress.ip_address(peer[0]) != ipaddress.ip_address(target)
                    or peer[1] != port
                ):
                    raise ValueError("connected_peer_mismatch")
                return stream
        except BaseException as exc:
            if stream is not None:
                await stream.aclose()
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise httpcore.ConnectError("tcp_destination_validation_failed") from None


class PinnedTcpTransport(httpx.AsyncHTTPTransport):
    def __init__(self, config, resolver=None):
        self._pool = httpcore.AsyncConnectionPool(
            retries=0,
            network_backend=PinnedTcpBackend(config, resolver),
            max_connections=4,
            max_keepalive_connections=0,
        )
