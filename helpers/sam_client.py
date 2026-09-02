"""Typed SAM node client built on the plugin-owned MCP transport."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping

from .domain import MeshModel, ToolDescriptor, TransportConfig
from .mcp_transport import McpStreamableSession, Resolver, SamProviderError, SamSchemaError


@dataclass(frozen=True)
class NodeHealth:
    ready: bool
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class McpCapabilities:
    server_name: str
    server_version: str
    protocol_version: str
    capabilities: Mapping[str, Any]
    instructions: str


@dataclass(frozen=True)
class ToolResult:
    content: tuple[Mapping[str, Any], ...]
    structured: Mapping[str, Any]
    is_error: bool


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _schema_hash(input_schema: Mapping[str, Any], output_schema: Mapping[str, Any] | None) -> str:
    value = {"input_schema": input_schema, "output_schema": output_schema}
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _object(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SamSchemaError(f"{name} must be an object")
    return value


class SamClient:
    """SAM health, MCP, and aggregate model facade client."""

    def __init__(
        self,
        config: TransportConfig,
        *,
        timeout_seconds: float = 30.0,
        resolver: Resolver | None = None,
    ) -> None:
        self.mcp = McpStreamableSession(
            config,
            timeout_seconds=timeout_seconds,
            resolver=resolver,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(mcp={self.mcp!r})"

    async def __aenter__(self) -> "SamClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self.mcp.aclose()

    async def health(self) -> NodeHealth:
        payload = _object(await self.mcp.get_json("/healthz"), "health response")
        ready = payload.get("ready") is True or payload.get("status") in {"ok", "healthy"}
        return NodeHealth(ready=ready, payload=dict(payload))

    async def readiness(self) -> NodeHealth:
        payload = _object(await self.mcp.get_json("/readyz"), "readiness response")
        ready = payload.get("ready") is True or payload.get("status") == "ready"
        return NodeHealth(ready=ready, payload=dict(payload))

    async def initialize_mcp(self) -> McpCapabilities:
        result = _object(await self.mcp.initialize(), "MCP initialize result")
        server_info = _object(result.get("serverInfo"), "MCP serverInfo")
        name = server_info.get("name")
        version = server_info.get("version")
        protocol = result.get("protocolVersion")
        capabilities = _object(result.get("capabilities"), "MCP capabilities")
        instructions = result.get("instructions", "")
        if not all(isinstance(item, str) and item for item in (name, version, protocol)):
            raise SamSchemaError("MCP initialize metadata must contain nonempty strings")
        if not isinstance(instructions, str):
            raise SamSchemaError("MCP instructions must be a string")
        return McpCapabilities(
            server_name=name,
            server_version=version,
            protocol_version=protocol,
            capabilities=dict(capabilities),
            instructions=instructions,
        )

    async def list_tools(self) -> list[ToolDescriptor]:
        result = _object(await self.mcp.request("tools/list", {}), "MCP tools/list result")
        tools = result.get("tools")
        if not isinstance(tools, list):
            raise SamSchemaError("MCP tools/list tools must be an array")
        observed: list[ToolDescriptor] = []
        names: set[str] = set()
        discovered_at = _timestamp()
        for index, value in enumerate(tools):
            tool = _object(value, f"MCP tool {index}")
            name = tool.get("name")
            description = tool.get("description", "")
            input_schema = tool.get("inputSchema")
            output_schema = tool.get("outputSchema")
            if not isinstance(name, str) or not name or name in names:
                raise SamSchemaError("MCP tool names must be unique nonempty strings")
            if not isinstance(description, str):
                raise SamSchemaError("MCP tool descriptions must be strings")
            input_schema = _object(input_schema, f"MCP tool {name} inputSchema")
            if output_schema is not None:
                output_schema = _object(output_schema, f"MCP tool {name} outputSchema")
            try:
                schema_hash = _schema_hash(input_schema, output_schema)
                descriptor = ToolDescriptor(
                    canonical_uri=f"mcp://sam-node/{name}",
                    peer_id="",
                    service="sam-node",
                    description=description,
                    input_schema=dict(input_schema),
                    output_schema=None if output_schema is None else dict(output_schema),
                    labels=(),
                    discovered_at=discovered_at,
                    discovery_source="mcp_tools_list",
                    schema_hash=schema_hash,
                )
            except (TypeError, ValueError) as exc:
                raise SamSchemaError(f"MCP tool {name} contains an invalid schema") from exc
            names.add(name)
            observed.append(descriptor)
        return observed

    async def call_mcp_tool(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        result = _object(await self.mcp.call_tool(name, arguments), "MCP tool result")
        content = result.get("content", [])
        structured = result.get("structuredContent", result.get("structured", {}))
        is_error = result.get("isError", False)
        if not isinstance(content, list) or not all(isinstance(item, Mapping) for item in content):
            raise SamSchemaError("MCP tool content must be an array of objects")
        structured = _object(structured, "MCP structured tool result")
        if not isinstance(is_error, bool):
            raise SamSchemaError("MCP tool isError must be a boolean")
        if is_error:
            raise SamProviderError("SAM MCP tool returned an application error")
        return ToolResult(
            content=tuple(dict(item) for item in content),
            structured=dict(structured),
            is_error=is_error,
        )

    async def list_models(self) -> list[MeshModel]:
        payload = _object(await self.mcp.get_json("/v1/models"), "model-list response")
        values = payload.get("data")
        if not isinstance(values, list):
            raise SamSchemaError("model-list data must be an array")
        discovered_at = _timestamp()
        models: list[MeshModel] = []
        seen: set[str] = set()
        for index, value in enumerate(values):
            model = _object(value, f"model-list item {index}")
            model_id = model.get("id")
            owned_by = model.get("owned_by", "sam")
            if not isinstance(model_id, str) or not model_id.strip():
                raise SamSchemaError("model IDs must be nonempty strings")
            if not isinstance(owned_by, str) or not owned_by:
                raise SamSchemaError("model owned_by must be a nonempty string")
            if model_id in seen:
                continue
            seen.add(model_id)
            models.append(
                MeshModel(
                    id=model_id,
                    owned_by=owned_by,
                    peer_id=None,
                    service=None,
                    labels=(),
                    local_proxy_url=None,
                    discovered_at=discovered_at,
                    discovery_source="aggregate_v1_models",
                )
            )
        return models
