"""Typed SAM node client built on the plugin-owned MCP transport."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from .domain import MeshModel, ToolDescriptor, TransportConfig
from .mcp_transport import (
    McpStreamableSession,
    Resolver,
    SamCallAmbiguous,
    SamProviderError,
    SamSchemaError,
)


def _freeze_json(value: Any, path: str) -> Any:
    """Deep-copy JSON into immutable containers."""
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise SamSchemaError(f"{path} must contain string object keys")
            frozen[key] = _freeze_json(item, f"{path}.{key}")
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item, f"{path}[]") for item in value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise SamSchemaError(f"{path} must contain finite JSON values")


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_json(item) for item in value]
    return value


@dataclass(frozen=True)
class NodeHealth:
    ready: bool
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload", _freeze_json(self.payload, "health payload"))


@dataclass(frozen=True)
class McpCapabilities:
    server_name: str
    server_version: str
    protocol_version: str
    capabilities: Mapping[str, Any]
    instructions: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "capabilities",
            _freeze_json(self.capabilities, "MCP capabilities"),
        )


@dataclass(frozen=True)
class ToolResult:
    content: tuple[Mapping[str, Any], ...]
    structured: Mapping[str, Any]
    is_error: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "content", _freeze_json(self.content, "tool content"))
        object.__setattr__(
            self,
            "structured",
            _freeze_json(self.structured, "structured tool result"),
        )


@dataclass(frozen=True)
class McpTool:
    """Observed MCP tool with its exact wire name and optional canonical identity."""

    wire_name: str
    canonical_uri: str | None
    description: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any] | None
    schema_hash: str
    descriptor: ToolDescriptor | None
    annotations: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "input_schema",
            _freeze_json(self.input_schema, "tool input schema"),
        )
        if self.output_schema is not None:
            object.__setattr__(
                self,
                "output_schema",
                _freeze_json(self.output_schema, "tool output schema"),
            )
        annotations = _freeze_json(self.annotations, "tool annotations")
        if not isinstance(annotations, Mapping):
            raise SamSchemaError("tool annotations must be an object")
        object.__setattr__(self, "annotations", annotations)


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _schema_hash(
    input_schema: Mapping[str, Any], output_schema: Mapping[str, Any] | None
) -> str:
    value = {
        "input_schema": _plain_json(input_schema),
        "output_schema": _plain_json(output_schema),
    }
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _object(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SamSchemaError(f"{name} must be an object")
    return value


def _validate_tool_annotations(value: Mapping[str, Any], name: str) -> None:
    boolean_hints = (
        "readOnlyHint",
        "destructiveHint",
        "idempotentHint",
        "openWorldHint",
    )
    for hint in boolean_hints:
        if hint in value and not isinstance(value[hint], bool):
            raise SamSchemaError(f"MCP tool {name} annotation {hint} must be boolean")
    if "title" in value and not isinstance(value["title"], str):
        raise SamSchemaError(f"MCP tool {name} annotation title must be a string")


def _canonical_tool_uri(value: str) -> str | None:
    if not value.startswith("mcp://"):
        return None
    parsed = urlsplit(value)
    if parsed.scheme != "mcp" or not parsed.netloc or not parsed.path.strip("/"):
        raise SamSchemaError("canonical MCP tool names must include service and tool")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise SamSchemaError("canonical MCP tool names must not contain URL metadata")
    return value


def _validated_service_uri(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = urlsplit(value)
    if (
        parsed.scheme != "mcp"
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise SamSchemaError("local MCP service identity must be mcp://<service>")
    return value.rstrip("/")


class SamClient:
    """SAM health, MCP, and aggregate model facade client."""

    def __init__(
        self,
        config: TransportConfig,
        *,
        timeout_seconds: float = 30.0,
        resolver: Resolver | None = None,
        local_service_uri: str | None = None,
    ) -> None:
        self._local_service_uri = _validated_service_uri(local_service_uri)
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
        ready = payload.get("ready") is True or payload.get("status") in {
            "ok",
            "healthy",
        }
        return NodeHealth(ready=ready, payload=payload)

    async def readiness(self) -> NodeHealth:
        payload = _object(await self.mcp.get_json("/readyz"), "readiness response")
        ready = payload.get("ready") is True or payload.get("status") == "ready"
        return NodeHealth(ready=ready, payload=payload)

    async def initialize_mcp(self) -> McpCapabilities:
        result = _object(await self.mcp.initialize(), "MCP initialize result")
        server_info = _object(result.get("serverInfo"), "MCP serverInfo")
        name = server_info.get("name")
        version = server_info.get("version")
        protocol = result.get("protocolVersion")
        capabilities = _object(result.get("capabilities"), "MCP capabilities")
        instructions = result.get("instructions", "")
        if not all(
            isinstance(item, str) and item for item in (name, version, protocol)
        ):
            raise SamSchemaError("MCP initialize metadata must contain nonempty strings")
        if not isinstance(instructions, str):
            raise SamSchemaError("MCP instructions must be a string")
        return McpCapabilities(
            server_name=name,
            server_version=version,
            protocol_version=protocol,
            capabilities=capabilities,
            instructions=instructions,
        )

    async def list_tools(self) -> list[McpTool]:
        result = _object(
            await self.mcp.request("tools/list", {}),
            "MCP tools/list result",
        )
        tools = result.get("tools")
        if not isinstance(tools, list):
            raise SamSchemaError("MCP tools/list tools must be an array")
        observed: list[McpTool] = []
        names: set[str] = set()
        discovered_at = _timestamp()
        for index, value in enumerate(tools):
            tool = _object(value, f"MCP tool {index}")
            wire_name = tool.get("name")
            description = tool.get("description", "")
            input_schema = tool.get("inputSchema")
            output_schema = tool.get("outputSchema")
            annotations = tool.get("annotations", {})
            if not isinstance(wire_name, str) or not wire_name or wire_name in names:
                raise SamSchemaError("MCP tool names must be unique nonempty strings")
            if not isinstance(description, str):
                raise SamSchemaError("MCP tool descriptions must be strings")
            input_schema = _object(input_schema, f"MCP tool {wire_name} inputSchema")
            annotations = _object(annotations, f"MCP tool {wire_name} annotations")
            _validate_tool_annotations(annotations, wire_name)
            if output_schema is not None:
                output_schema = _object(
                    output_schema,
                    f"MCP tool {wire_name} outputSchema",
                )
            frozen_input = _freeze_json(input_schema, "tool input schema")
            frozen_output = (
                None
                if output_schema is None
                else _freeze_json(output_schema, "tool output schema")
            )
            frozen_annotations = _freeze_json(annotations, "tool annotations")
            schema_hash = _schema_hash(frozen_input, frozen_output)
            canonical_uri = _canonical_tool_uri(wire_name)
            if canonical_uri is None and self._local_service_uri is not None:
                canonical_uri = f"{self._local_service_uri}/{wire_name}"
            descriptor = None
            if canonical_uri is not None:
                try:
                    parsed = urlsplit(canonical_uri)
                    descriptor = ToolDescriptor(
                        canonical_uri=canonical_uri,
                        peer_id="",
                        service=f"mcp://{parsed.netloc}",
                        description=description,
                        input_schema=frozen_input,
                        output_schema=frozen_output,
                        labels=(),
                        discovered_at=discovered_at,
                        discovery_source="mcp_tools_list",
                        schema_hash=schema_hash,
                        annotations=frozen_annotations,
                    )
                except (TypeError, ValueError) as exc:
                    raise SamSchemaError(
                        f"MCP tool {wire_name} contains an invalid schema"
                    ) from exc
            observed.append(
                McpTool(
                    wire_name=wire_name,
                    canonical_uri=canonical_uri,
                    description=description,
                    input_schema=frozen_input,
                    output_schema=frozen_output,
                    schema_hash=schema_hash,
                    descriptor=descriptor,
                    annotations=frozen_annotations,
                )
            )
            names.add(wire_name)
        return observed

    async def call_mcp_tool(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> ToolResult:
        result = await self.mcp.call_tool(name, arguments)
        try:
            result = _object(result, "MCP tool result")
            content = result.get("content", [])
            structured = result.get(
                "structuredContent",
                result.get("structured", {}),
            )
            is_error = result.get("isError", False)
            if not isinstance(content, list) or not all(
                isinstance(item, Mapping) for item in content
            ):
                raise SamSchemaError(
                    "MCP tool content must be an array of objects"
                )
            structured = _object(structured, "MCP structured tool result")
            if not isinstance(is_error, bool):
                raise SamSchemaError("MCP tool isError must be a boolean")
        except SamSchemaError as exc:
            raise SamCallAmbiguous(
                "SAM tools/call returned an unusable tool result",
                phase="response",
                dispatched=True,
            ) from exc
        if is_error:
            raise SamProviderError("SAM MCP tool returned an application error")
        return ToolResult(
            content=tuple(content),
            structured=structured,
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
                raise SamSchemaError("model IDs must be unique")
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
