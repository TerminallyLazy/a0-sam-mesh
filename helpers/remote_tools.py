"""Source-pinned SAM text-content discovery and exact remote-call adapter."""

import json
from datetime import UTC, datetime
from urllib.parse import urlsplit

from .capabilities import CALL_REMOTE_TOOL_SCHEMA, EXPECTED_READ_TOOL_SCHEMAS, _schema_matches
from .domain import ToolDescriptor
from .mcp_transport import SamSchemaError
from .sam_client import _schema_hash


class RemoteTools:
    # SAM remoteToolDescription drops MCP annotations. Absence is not proof of
    # unchanged risk metadata. Missing annotations impose the gate UNKNOWN lease floor.
    risk_metadata_verified = False
    observation_contract = "sam-describe/v1"

    def __init__(self, client):
        self.client = client

    @property
    def transport_verified(self):
        from .tcp_transport import PinnedTcpTransport
        from .uds_transport import PinnedUnixTransport

        return isinstance(
            self.client.mcp._client._transport, (PinnedTcpTransport, PinnedUnixTransport)
        )

    def check_transport(self):
        if not self.transport_verified:
            raise SamSchemaError("unverified_route")

    async def _check_schema(self, name):
        self.check_transport()
        tools = await self.client.list_tools()
        matches = [tool for tool in tools if tool.wire_name == name]
        expected = (
            CALL_REMOTE_TOOL_SCHEMA
            if name == "call_remote_tool"
            else EXPECTED_READ_TOOL_SCHEMAS.get(name)
        )
        if (
            expected is None
            or len(matches) != 1
            or not _schema_matches(matches[0].input_schema, expected)
        ):
            raise SamSchemaError("schema_changed")

    async def read(self, name, arguments):
        if name not in EXPECTED_READ_TOOL_SCHEMAS:
            raise SamSchemaError("unsupported_capability")
        await self._check_schema(name)
        result = await self.client.call_mcp_tool(name, arguments)
        allowed_count = (
            2 if name == "discover_remote_services" and arguments.get("type") == "inference" else 1
        )
        if (
            not 1 <= len(result.content) <= allowed_count
            or any(part.get("type") != "text" for part in result.content)
            or result.content[0].get("type") != "text"
            or not isinstance(result.content[0].get("text"), str)
        ):
            raise SamSchemaError("schema_changed")
        try:
            return json.loads(result.content[0]["text"])
        except (ValueError, TypeError):
            raise SamSchemaError("schema_changed") from None

    async def describe(self, peer_id, tool_name):
        await self._check_schema("call_remote_tool")
        value = await self.read(
            "describe_remote_tool", {"peer_id": peer_id, "tool_name": tool_name}
        )
        required = {"peer_id", "tool_name", "description", "input_schema"}
        if (
            not isinstance(value, dict)
            or not required <= value.keys()
            or value.keys() - required - {"output_schema"}
            or value["peer_id"] != peer_id
            or value["tool_name"] != tool_name
            or not isinstance(value["description"], str)
            or not isinstance(value["input_schema"], dict)
        ):
            raise SamSchemaError("schema_changed")
        parsed = urlsplit(tool_name)
        if (
            parsed.scheme != "mcp"
            or not parsed.netloc
            or not parsed.path.strip("/")
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise SamSchemaError("invalid_canonical_identifier")
        return ToolDescriptor(
            tool_name,
            peer_id,
            "mcp://" + parsed.netloc,
            value["description"],
            value["input_schema"],
            value.get("output_schema"),
            (),
            datetime.now(UTC).isoformat(),
            "sam_describe_remote_tool",
            _schema_hash(value["input_schema"], value.get("output_schema")),
            annotation_provenance="unavailable",
        )

    async def call(self, descriptor, arguments, labels):
        self.check_transport()
        from .embassy_config import HTTP_CONTRACT_MARKER

        if descriptor.description.startswith(HTTP_CONTRACT_MARKER):
            # The HTTP proxy retains the exact peer but has no MCP label contract.
            # A self-described transport never relaxes risk/approval requirements.
            if labels:
                raise SamSchemaError("embassy_http_label_contract_unavailable")
            return await self.client.call_embassy_tool(
                descriptor.peer_id, descriptor.canonical_uri, arguments
            )
        # Schema must have been checked during preparation, never a network roundtrip
        # between gate lease consumption and the actual call.
        return await self.client.call_mcp_tool(
            "call_remote_tool",
            {
                "peer_id": descriptor.peer_id,
                "tool_name": descriptor.canonical_uri,
                "arguments": arguments,
                "required_labels": labels,
            },
        )
