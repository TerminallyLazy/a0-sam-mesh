from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from helpers.domain import TransportConfig
from tests.fakes.sam_sidecar import FakeResponse, FakeSamSidecar


TOKEN = "contract-only-sensitive-token"


def http_config(sidecar: FakeSamSidecar, token: str | None = TOKEN) -> TransportConfig:
    return TransportConfig(
        type="http",
        base_url=sidecar.base_url,
        socket_path=None,
        token=token,
        allowed_origins=(),
    )


def uds_config(sidecar: FakeSamSidecar, token: str | None = TOKEN) -> TransportConfig:
    return TransportConfig(
        type="uds",
        base_url=sidecar.base_url,
        socket_path=sidecar.uds_path,
        token=token,
        allowed_origins=(),
    )


class SamTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_session_preserves_opaque_headers_and_sends_initialized(self):
        from helpers.sam_client import SamClient

        async with FakeSamSidecar(required_token=TOKEN) as sidecar:
            async with SamClient(http_config(sidecar)) as client:
                report = await client.initialize_mcp()
                result = await client.call_mcp_tool("get_mesh_info", {})

        self.assertEqual(report.server_name, "sam-node-mcp")
        self.assertTrue(result.structured["connected"])
        self.assertEqual(sidecar.count_mcp_method("initialize"), 1)
        self.assertEqual(sidecar.count_mcp_method("notifications/initialized"), 1)
        notification = sidecar.received[1]
        self.assertNotIn("id", notification["json"])
        call_headers = sidecar.received[-1]["headers"]
        self.assertEqual(call_headers["mcp-session-id"], "session-123")
        self.assertEqual(call_headers["mcp-protocol-version"], "2025-03-26")
        self.assertEqual(call_headers["x-sam-authentication"], f"Bearer {TOKEN}")

    async def test_negotiated_protocol_from_initialize_result_is_reused(self):
        from helpers.sam_client import SamClient

        async with FakeSamSidecar(protocol_response_header=False) as sidecar:
            async with SamClient(http_config(sidecar, token=None)) as client:
                report = await client.initialize_mcp()
                await client.list_tools()

        self.assertEqual(report.protocol_version, "2025-03-26")
        self.assertEqual(
            sidecar.received[-1]["headers"]["mcp-protocol-version"],
            "2025-03-26",
        )

    async def test_uds_without_socket_path_fails_closed(self):
        from helpers.mcp_transport import McpStreamableSession, SamSchemaError

        config = TransportConfig(
            type="uds",
            base_url="http://sam.local",
            socket_path=None,
            token=TOKEN,
            allowed_origins=(),
        )
        with self.assertRaises(SamSchemaError):
            McpStreamableSession(config)

    async def test_uds_uses_http_over_socket_without_bearer(self):
        from helpers.sam_client import SamClient

        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "sam.sock")
            async with FakeSamSidecar(uds_path=path, required_token=TOKEN) as sidecar:
                async with SamClient(uds_config(sidecar)) as client:
                    health = await client.health()

        self.assertTrue(health.ready)
        self.assertEqual(sidecar.tcp_connections, 0)
        self.assertGreater(sidecar.uds_connections, 0)
        self.assertNotIn("x-sam-authentication", sidecar.received_headers[0])

    async def test_sse_accepts_crlf_comments_multiline_data_and_fragments(self):
        from helpers.sam_client import SamClient

        async with FakeSamSidecar() as sidecar:
            async with SamClient(http_config(sidecar, token=None)) as client:
                await client.initialize_mcp()
                request_id = client.mcp.next_request_id
                event = (
                    b": heartbeat\r\n"
                    b"event: message\r\n"
                    b"data: {\"jsonrpc\":\"2.0\",\r\n"
                    + f"data: \"id\":{request_id},\"result\":{{\"tools\":[]}}}}\r\n\r\n".encode()
                )
                sidecar.override(
                    "/mcp",
                    FakeResponse(
                        200,
                        content_type="text/event-stream; charset=utf-8",
                        body=event,
                        fragments=(1, 2, 5, 3, 8, 1),
                    ),
                    method="POST",
                )
                tools = await client.list_tools()

        self.assertEqual(tools, [])

    async def test_status_and_machine_errors_have_distinct_types(self):
        from helpers.mcp_transport import (
            SamAuthRejected,
            SamAuthRequired,
            SamNodeNotReady,
            SamPolicyDenied,
        )
        from helpers.sam_client import SamClient

        cases = (
            (401, SamAuthRequired),
            (403, SamAuthRejected),
            (503, SamNodeNotReady),
        )
        for status, expected in cases:
            async with FakeSamSidecar() as sidecar:
                sidecar.override("/healthz", FakeResponse(status, body=b"{}"))
                async with SamClient(http_config(sidecar, token=None)) as client:
                    with self.subTest(status=status):
                        with self.assertRaises(expected):
                            await client.health()

        async with FakeSamSidecar() as sidecar:
            async with SamClient(http_config(sidecar, token=None)) as client:
                await client.initialize_mcp()
                with self.assertRaises(SamPolicyDenied):
                    await client.call_mcp_tool("policy_denied", {})

    async def test_outer_403_is_auth_rejected_even_with_machine_body(self):
        from helpers.mcp_transport import SamAuthRejected
        from helpers.sam_client import SamClient

        body = b'{"error":{"code":"policy_denied","message":"denied"}}'
        async with FakeSamSidecar() as sidecar:
            sidecar.override("/healthz", FakeResponse(403, body=body))
            async with SamClient(http_config(sidecar, token=None)) as client:
                with self.assertRaises(SamAuthRejected):
                    await client.health()

    async def test_redirects_media_malformed_and_oversized_fail_closed(self):
        from helpers.mcp_transport import SamSchemaError
        from helpers.sam_client import SamClient

        cases = (
            FakeResponse(302, headers={"Location": "http://attacker.invalid"}),
            FakeResponse(200, content_type="text/html", body=b"not json"),
            FakeResponse(200, body=b"{"),
            FakeResponse(200, body=b"x" * (4 * 1024 * 1024 + 1)),
        )
        for response in cases:
            async with FakeSamSidecar() as sidecar:
                sidecar.override("/healthz", response)
                async with SamClient(http_config(sidecar, token=None)) as client:
                    with self.subTest(response=response):
                        with self.assertRaises(SamSchemaError):
                            await client.health()

    async def test_transport_eof_is_connectivity_and_tool_call_is_not_replayed(self):
        from helpers.mcp_transport import SamConnectivityError
        from helpers.sam_client import SamClient

        async with FakeSamSidecar() as sidecar:
            async with SamClient(http_config(sidecar, token=None)) as client:
                await client.initialize_mcp()
                sidecar.override(
                    "/mcp",
                    FakeResponse(200, close_without_response=True),
                    method="POST",
                )
                with self.assertRaises(SamConnectivityError):
                    await client.call_mcp_tool("get_mesh_info", {})
        self.assertEqual(sidecar.count_mcp_method("tools/call"), 1)

    async def test_timeout_is_connectivity_error(self):
        from helpers.mcp_transport import SamConnectivityError
        from helpers.sam_client import SamClient

        async with FakeSamSidecar() as sidecar:
            sidecar.override("/healthz", FakeResponse(200, delay=0.05, body=b"{}"))
            async with SamClient(
                http_config(sidecar, token=None), timeout_seconds=0.01
            ) as client:
                with self.assertRaises(SamConnectivityError):
                    await client.health()

    async def test_nonlocal_hostname_resolution_to_loopback_is_rejected(self):
        from helpers.mcp_transport import SamConnectivityError, validate_tcp_origin

        config = TransportConfig(
            type="http",
            base_url="https://sam.example:8443",
            socket_path=None,
            token=None,
            allowed_origins=("https://sam.example:8443",),
        )

        async def loopback(*_args):
            return [(0, 0, 0, "", ("127.0.0.1", 8443))]

        with self.assertRaises(SamConnectivityError):
            await validate_tcp_origin(config, resolver=loopback)

    async def test_tcp_resolution_rejects_forbidden_classes_and_origin_mismatch(self):
        from helpers.mcp_transport import SamConnectivityError, validate_tcp_origin

        config = TransportConfig(
            type="http",
            base_url="https://sam.example:8443/v1",
            socket_path=None,
            token=None,
            allowed_origins=("https://sam.example:8443",),
        )

        async def link_local(*_args):
            return [(0, 0, 0, "", ("169.254.169.254", 8443))]

        with self.assertRaises(SamConnectivityError):
            await validate_tcp_origin(config, resolver=link_local)

        async def public(*_args):
            return [(0, 0, 0, "", ("203.0.113.7", 8443))]

        changed = copy.copy(config)
        object.__setattr__(changed, "allowed_origins", ("https://other.example:8443",))
        with self.assertRaises(SamConnectivityError):
            await validate_tcp_origin(changed, resolver=public)

    async def test_transport_reprs_and_errors_never_include_token(self):
        from helpers.mcp_transport import McpStreamableSession, SamAuthRequired

        async with FakeSamSidecar(required_token="different-contract-token") as sidecar:
            config = http_config(sidecar)
            session = McpStreamableSession(config)
            try:
                self.assertNotIn(TOKEN, repr(session))
                with self.assertRaises(SamAuthRequired) as raised:
                    await session.get_json("/missing-auth")
                self.assertNotIn(TOKEN, repr(raised.exception))
                self.assertNotIn(TOKEN, str(raised.exception))
            finally:
                await session.aclose()

    async def test_tcp_addresses_are_revalidated_before_each_request(self):
        from helpers.mcp_transport import SamConnectivityError
        from helpers.sam_client import SamClient

        resolutions = iter(("127.0.0.1", "169.254.169.254"))

        async def changing_resolver(*_args):
            return [(0, 0, 0, "", (next(resolutions), 80))]

        async with FakeSamSidecar() as sidecar:
            async with SamClient(
                http_config(sidecar, token=None), resolver=changing_resolver
            ) as client:
                self.assertTrue((await client.health()).ready)
                with self.assertRaises(SamConnectivityError):
                    await client.health()




class SamTransportFixRound1Tests(unittest.IsolatedAsyncioTestCase):
    async def test_initialize_rejects_bool_id_without_committing_session(self):
        from helpers.mcp_transport import SamSchemaError
        from helpers.sam_client import SamClient

        body = (
            b'{"jsonrpc":"2.0","id":true,"result":'
            b'{"protocolVersion":"2025-03-26"}}'
        )
        headers = {
            "Mcp-Session-Id": "must-not-commit",
            "Mcp-Protocol-Version": "2025-03-26",
        }
        async with FakeSamSidecar() as sidecar:
            sidecar.mcp_overrides["initialize"] = FakeResponse(
                200,
                body=body,
                headers=headers,
            )
            async with SamClient(http_config(sidecar, token=None)) as client:
                with self.assertRaises(SamSchemaError):
                    await client.initialize_mcp()
                self.assertIsNone(client.mcp.session_id)
                self.assertIsNone(client.mcp.protocol_version)

    async def test_initialize_failure_commits_no_partial_session_state(self):
        from helpers.mcp_transport import SamSchemaError
        from helpers.sam_client import SamClient

        body = (
            b'{"jsonrpc":"2.0","id":1,"result":'
            b'{"protocolVersion":"2025-03-26"}}'
        )
        headers = {
            "Mcp-Session-Id": "must-not-commit",
            "Mcp-Protocol-Version": "different-version",
        }
        async with FakeSamSidecar() as sidecar:
            sidecar.mcp_overrides["initialize"] = FakeResponse(
                200,
                body=body,
                headers=headers,
            )
            async with SamClient(http_config(sidecar, token=None)) as client:
                with self.assertRaises(SamSchemaError):
                    await client.initialize_mcp()
                self.assertIsNone(client.mcp.session_id)
                self.assertIsNone(client.mcp.protocol_version)

    async def test_initialize_validates_full_result_before_session_commit(self):
        from helpers.mcp_transport import SamSchemaError
        from helpers.sam_client import SamClient

        body = (
            b'{"jsonrpc":"2.0","id":1,"result":'
            b'{"protocolVersion":"2025-03-26","capabilities":{},'
            b'"serverInfo":{"name":"","version":"0.1.0"}}}'
        )
        headers = {"Mcp-Session-Id": "must-not-commit"}
        async with FakeSamSidecar() as sidecar:
            sidecar.mcp_overrides["initialize"] = FakeResponse(
                200,
                body=body,
                headers=headers,
            )
            async with SamClient(http_config(sidecar, token=None)) as client:
                with self.assertRaises(SamSchemaError):
                    await client.initialize_mcp()
                self.assertIsNone(client.mcp.session_id)
                self.assertIsNone(client.mcp.protocol_version)

    async def test_float_id_alias_is_rejected_even_with_exact_id_present(self):
        from helpers.mcp_transport import SamSchemaError
        from helpers.sam_client import SamClient

        body = (
            b'data: {"jsonrpc":"2.0","id":1.0,"result":{}}\n\n'
            b'data: {"jsonrpc":"2.0","id":1,"result":'
            b'{"protocolVersion":"2025-03-26","capabilities":{},'
            b'"serverInfo":{"name":"sam-node-mcp","version":"0.1.0"}}}\n\n'
        )
        headers = {"Mcp-Session-Id": "must-not-commit"}
        async with FakeSamSidecar() as sidecar:
            sidecar.mcp_overrides["initialize"] = FakeResponse(
                200,
                content_type="text/event-stream",
                body=body,
                headers=headers,
            )
            async with SamClient(http_config(sidecar, token=None)) as client:
                with self.assertRaises(SamSchemaError):
                    await client.initialize_mcp()
                self.assertIsNone(client.mcp.session_id)

    async def test_initialize_rejects_unsupported_protocol_without_state(self):
        from helpers.mcp_transport import SamSchemaError
        from helpers.sam_client import SamClient

        body = (
            b'{"jsonrpc":"2.0","id":1,"result":'
            b'{"protocolVersion":"2099-01-01","capabilities":{},'
            b'"serverInfo":{"name":"sam-node-mcp","version":"0.1.0"}}}'
        )
        headers = {"Mcp-Session-Id": "must-not-commit"}
        async with FakeSamSidecar() as sidecar:
            sidecar.mcp_overrides["initialize"] = FakeResponse(
                200,
                body=body,
                headers=headers,
            )
            async with SamClient(http_config(sidecar, token=None)) as client:
                with self.assertRaises(SamSchemaError):
                    await client.initialize_mcp()
                self.assertIsNone(client.mcp.session_id)
                self.assertIsNone(client.mcp.protocol_version)

    async def test_malformed_json_rpc_error_is_schema_error(self):
        from helpers.mcp_transport import SamSchemaError
        from helpers.sam_client import SamClient

        body = b'{"jsonrpc":"2.0","id":2,"error":{"code":false}}'
        async with FakeSamSidecar() as sidecar:
            async with SamClient(http_config(sidecar, token=None)) as client:
                await client.initialize_mcp()
                sidecar.mcp_overrides["tools/list"] = FakeResponse(200, body=body)
                with self.assertRaises(SamSchemaError):
                    await client.list_tools()

    async def test_tool_response_loss_is_explicitly_ambiguous_and_not_replayed(self):
        from helpers.mcp_transport import SamCallAmbiguous
        from helpers.sam_client import SamClient

        async with FakeSamSidecar() as sidecar:
            async with SamClient(http_config(sidecar, token=None)) as client:
                await client.initialize_mcp()
                sidecar.mcp_overrides["tools/call"] = FakeResponse(
                    200,
                    close_without_response=True,
                )
                with self.assertRaises(SamCallAmbiguous) as raised:
                    await client.call_mcp_tool("get_mesh_info", {})
        self.assertIsNone(raised.exception.dispatched)
        self.assertTrue(raised.exception.duplicate_execution_possible)
        self.assertEqual(raised.exception.phase, "dispatch_or_response")
        self.assertEqual(sidecar.count_mcp_method("tools/call"), 1)

    async def test_exact_four_mib_json_succeeds(self):
        from helpers.mcp_transport import MCP_RESPONSE_MAX_BYTES
        from helpers.sam_client import SamClient

        prefix = b'{"ready":true,"padding":"'
        suffix = b'"}'
        body = prefix + b"x" * (MCP_RESPONSE_MAX_BYTES - len(prefix) - len(suffix)) + suffix
        self.assertEqual(len(body), MCP_RESPONSE_MAX_BYTES)
        async with FakeSamSidecar() as sidecar:
            sidecar.override("/healthz", FakeResponse(200, body=body))
            async with SamClient(http_config(sidecar, token=None)) as client:
                self.assertTrue((await client.health()).ready)

    async def test_fragmented_sse_cumulative_overflow_is_rejected(self):
        from helpers.mcp_transport import MCP_RESPONSE_MAX_BYTES, SamSchemaError
        from helpers.sam_client import SamClient

        body = b"data: " + b"x" * MCP_RESPONSE_MAX_BYTES + b"\n\n"
        async with FakeSamSidecar() as sidecar:
            sidecar.override(
                "/healthz",
                FakeResponse(
                    200,
                    content_type="text/event-stream",
                    body=body,
                    fragments=(1024,) * 4096,
                ),
            )
            async with SamClient(http_config(sidecar, token=None)) as client:
                with self.assertRaises(SamSchemaError):
                    await client.health()


if __name__ == "__main__":
    unittest.main()
