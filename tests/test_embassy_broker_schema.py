"""Real FastMCP descriptors remain consumable by the governed schema subset."""

import unittest
from unittest.mock import patch


class EmbassyBrokerSchemaTests(unittest.IsolatedAsyncioTestCase):
    async def test_emitted_ask_schema_validates_and_missing_session_starts_new_request(self):
        from fastmcp import Client

        from helpers.embassy_broker import create_embassy_mcp
        from helpers.embassy_config import EmbassyService
        from helpers.embassy_sessions import VerifiedOrigin
        from helpers.schema_guard import validate_payload

        seen = []

        class Manager:
            async def ask(self, service, origin, request):
                seen.append(request)
                return {"response": "answer"}

        async def origin(request):
            return VerifiedOrigin("peer", "boundary")

        with patch("fastmcp.server.dependencies.get_http_request", return_value=object()):
            mcp = create_embassy_mcp(
                EmbassyService("research-desk", "research", "specialist"), Manager(), origin
            )
        async with Client(mcp) as client:
            descriptor = next(
                tool for tool in await client.list_tools() if tool.name == "ask_specialist"
            )
            for args in (
                {"message": "first"},
                {"message": "empty", "session_id": ""},
                {"message": "continued", "session_id": "A" * 32},
            ):
                validate_payload(descriptor.inputSchema, args)
                result = await client.call_tool("ask_specialist", args)
                self.assertFalse(result.is_error)
            self.assertEqual(
                seen,
                [
                    {"message": "first"},
                    {"message": "empty"},
                    {"message": "continued", "session_id": "A" * 32},
                ],
            )
            for args in (
                {"message": "invalid", "session_id": None},
                {"message": "invalid", "project": "other"},
            ):
                with self.assertRaisesRegex(Exception, "invalid_arguments"):
                    validate_payload(descriptor.inputSchema, args)
