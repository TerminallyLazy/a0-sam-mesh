"""Small dependency-free HTTP/1.1 SAM sidecar used by contract tests."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CURRENT_TOOLS = [
    {
        "name": "send_message",
        "description": "Send a message",
        "inputSchema": {
            "type": "object",
            "properties": {"peer_id": {"type": "string"}, "message": {"type": "string"}},
            "required": ["peer_id", "message"],
        },
    },
    {
        "name": "list_local_services",
        "description": "List local services",
        "inputSchema": {
            "type": "object",
            "properties": {"type": {"type": "string"}},
        },
    },
    {
        "name": "discover_remote_services",
        "description": "Discover remote services",
        "inputSchema": {
            "type": "object",
            "properties": {
                "type": {"type": "string"},
                "name": {"type": "string"},
                "limit": {"type": "integer"},
                "offset": {"type": "integer"},
            },
            "required": ["type"],
        },
    },
    {
        "name": "mesh_pubsub_broadcast",
        "description": "Publish an event",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "poll_messages",
        "description": "Poll messages",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "subscribe_topic",
        "description": "Subscribe",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_mesh_info",
        "description": "Get mesh information",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "call_remote_tool",
        "description": "Call a remote MCP tool",
        "inputSchema": {
            "type": "object",
            "properties": {
                "peer_id": {"type": "string"},
                "tool_name": {"type": "string"},
                "arguments": {"type": "object"},
                "required_labels": {"type": "string"},
            },
            "required": ["peer_id", "tool_name"],
        },
    },
    {
        "name": "find_remote_tools",
        "description": "Find remote tools",
        "inputSchema": {
            "type": "object",
            "properties": {
                "intent": {"type": "string"},
                "peer_id": {"type": "string"},
                "service_name": {"type": "string"},
                "tool_name": {"type": "string"},
            },
        },
    },
    {
        "name": "describe_remote_tool",
        "description": "Describe a remote tool",
        "inputSchema": {
            "type": "object",
            "properties": {
                "peer_id": {"type": "string"},
                "tool_name": {"type": "string"},
            },
            "required": ["peer_id", "tool_name"],
        },
    },
]


@dataclass
class FakeResponse:
    status: int
    content_type: str = "application/json"
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    fragments: tuple[int, ...] = ()
    close_without_response: bool = False
    delay: float = 0.0


class FakeSamSidecar:
    def __init__(
        self,
        *,
        uds_path: str | None = None,
        required_token: str | None = None,
        server_name: str = "sam-node-mcp",
        tools: list[dict[str, Any]] | None = None,
        models: Any = None,
        ready_payload: dict[str, Any] | None = None,
        protocol_response_header: bool = True,
    ) -> None:
        self.uds_path = uds_path
        self.required_token = required_token
        self.server_name = server_name
        self.tools = list(CURRENT_TOOLS if tools is None else tools)
        self.models = (
            {"object": "list", "data": [{"id": "mesh-model", "owned_by": "sam"}]}
            if models is None
            else models
        )
        self.ready_payload = {"ready": True} if ready_payload is None else ready_payload
        self.protocol_response_header = protocol_response_header
        self.received: list[dict[str, Any]] = []
        self.overrides: dict[tuple[str, str | None], FakeResponse] = {}
        self.mcp_overrides: dict[str, FakeResponse] = {}
        self.server: asyncio.AbstractServer | None = None
        self.base_url = ""
        self.tcp_connections = 0
        self.uds_connections = 0

    async def __aenter__(self) -> "FakeSamSidecar":
        if self.uds_path:
            path = Path(self.uds_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            self.server = await asyncio.start_unix_server(self._handle, path=self.uds_path)
            os.chmod(self.uds_path, 0o600)
            self.base_url = "http://sam.local"
        else:
            self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
            address = self.server.sockets[0].getsockname()
            self.base_url = f"http://127.0.0.1:{address[1]}"
        return self

    async def __aexit__(self, *_: object) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()
        if self.uds_path:
            try:
                Path(self.uds_path).unlink()
            except FileNotFoundError:
                pass

    def override(
        self,
        path: str,
        response: FakeResponse,
        *,
        method: str | None = None,
    ) -> None:
        self.overrides[(path, method)] = response

    @property
    def received_headers(self) -> list[dict[str, str]]:
        return [entry["headers"] for entry in self.received]

    def count_mcp_method(self, method: str) -> int:
        return sum(entry.get("json", {}).get("method") == method for entry in self.received)

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self.uds_path:
            self.uds_connections += 1
        else:
            self.tcp_connections += 1
        try:
            request_line = await reader.readline()
            if not request_line:
                return
            method, target, _ = request_line.decode("ascii").strip().split(" ", 2)
            headers: dict[str, str] = {}
            while True:
                line = await reader.readline()
                if line in {b"\r\n", b"\n", b""}:
                    break
                name, value = line.decode("latin-1").split(":", 1)
                headers[name.strip().lower()] = value.strip()
            content_length = int(headers.get("content-length", "0"))
            body = await reader.readexactly(content_length) if content_length else b""
            try:
                payload = json.loads(body) if body else None
            except json.JSONDecodeError:
                payload = None
            entry = {
                "method": method,
                "path": target,
                "headers": headers,
                "body": body,
                "json": payload,
            }
            self.received.append(entry)
            response = self._response(method, target, headers, payload)
            if response.delay:
                await asyncio.sleep(response.delay)
            if response.close_without_response:
                return
            await self._write_response(writer, response)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _response(
        self,
        method: str,
        target: str,
        headers: dict[str, str],
        payload: Any,
    ) -> FakeResponse:
        override = self.overrides.get((target, method)) or self.overrides.get((target, None))
        if override is not None:
            return override
        if self.required_token and not self.uds_path:
            expected = f"Bearer {self.required_token}"
            if headers.get("x-sam-authentication") != expected:
                return self._json(401, {"error": "authentication required"})
        if method == "GET" and target == "/healthz":
            return self._json(200, {"ready": True, "status": "ok"})
        if method == "GET" and target == "/readyz":
            return self._json(200, self.ready_payload)
        if method == "GET" and target == "/v1/models":
            return self._json(200, self.models)
        if method == "POST" and target == "/mcp":
            return self._mcp(payload)
        return self._json(404, {"error": "not found"})

    def _mcp(self, payload: Any) -> FakeResponse:
        method = payload.get("method") if isinstance(payload, dict) else None
        request_id = payload.get("id") if isinstance(payload, dict) else None
        if method in self.mcp_overrides:
            return self.mcp_overrides[method]
        if method == "initialize":
            return self._json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": self.server_name, "version": "0.1.0"},
                        "instructions": "fake mesh",
                    },
                },
                headers={
                    "Mcp-Session-Id": "session-123",
                    **(
                        {"Mcp-Protocol-Version": "2025-03-26"}
                        if self.protocol_response_header
                        else {}
                    ),
                },
            )
        if method == "notifications/initialized":
            return FakeResponse(status=202)
        if method == "tools/list":
            return self._json(
                200,
                {"jsonrpc": "2.0", "id": request_id, "result": {"tools": self.tools}},
            )
        if method == "tools/call":
            name = payload.get("params", {}).get("name")
            if name == "policy_denied":
                return self._json(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {
                            "code": "policy_denied",
                            "message": "remote policy denied the call",
                        },
                    },
                )
            return self._json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [{"type": "text", "text": "ok"}],
                        "structuredContent": {"connected": True, "tool": name},
                        "isError": False,
                    },
                },
            )
        return self._json(
            200,
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "method not found"},
            },
        )

    @staticmethod
    def _json(
        status: int,
        value: Any,
        *,
        headers: dict[str, str] | None = None,
    ) -> FakeResponse:
        return FakeResponse(
            status=status,
            body=json.dumps(value, separators=(",", ":")).encode("utf-8"),
            headers={} if headers is None else headers,
        )

    async def _write_response(
        self, writer: asyncio.StreamWriter, response: FakeResponse
    ) -> None:
        reason = {
            200: "OK",
            202: "Accepted",
            302: "Found",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            503: "Service Unavailable",
        }.get(response.status, "Response")
        lines = [
            f"HTTP/1.1 {response.status} {reason}\r\n",
            f"Content-Type: {response.content_type}\r\n",
            f"Content-Length: {len(response.body)}\r\n",
            "Connection: close\r\n",
        ]
        lines.extend(f"{name}: {value}\r\n" for name, value in response.headers.items())
        lines.append("\r\n")
        writer.write("".join(lines).encode("latin-1"))
        await writer.drain()
        if not response.fragments:
            writer.write(response.body)
            await writer.drain()
            return
        offset = 0
        for length in response.fragments:
            writer.write(response.body[offset : offset + length])
            offset += length
            await writer.drain()
        writer.write(response.body[offset:])
        await writer.drain()
