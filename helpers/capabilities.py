"""Runtime capability and exact SAM schema probes."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from .domain import MeshModel, ProbeStatus, ToolDescriptor
from .mcp_transport import (
    SamConnectivityError,
    SamError,
    SamProviderError,
    SamSchemaError,
)
from .sam_client import McpCapabilities, SamClient

EXPECTED_READ_TOOL_SCHEMAS: Mapping[str, Mapping[str, Any]] = MappingProxyType(
    {
        "get_mesh_info": {"properties": {}, "required": ()},
        "list_local_services": {"properties": {"type": "string"}, "required": ()},
        "discover_remote_services": {
            "properties": {
                "type": "string",
                "name": "string",
                "limit": "integer",
                "offset": "integer",
            },
            "required": ("type",),
        },
        "find_remote_tools": {
            "properties": {
                "intent": "string",
                "peer_id": "string",
                "service_name": "string",
                "tool_name": "string",
            },
            "required": (),
        },
        "describe_remote_tool": {
            "properties": {"peer_id": "string", "tool_name": "string"},
            "required": ("peer_id", "tool_name"),
        },
    }
)
REMOVED_DIAGNOSTIC_TOOLS = (
    "check_connectivity",
    "get_token_info",
    "get_network_info",
    "get_recent_logs",
)
_KNOWN_CURRENT_TOOLS = frozenset(
    {
        "send_message",
        "list_local_services",
        "discover_remote_services",
        "mesh_pubsub_broadcast",
        "poll_messages",
        "subscribe_topic",
        "get_mesh_info",
        "call_remote_tool",
        "find_remote_tools",
        "describe_remote_tool",
    }
)


@dataclass(frozen=True)
class FeatureProbe:
    status: ProbeStatus
    detail: str = ""


@dataclass(frozen=True)
class CompatibilityReport:
    status: ProbeStatus
    server_name: str | None
    server_version: str | None
    protocol_version: str | None
    features: Mapping[str, FeatureProbe]
    observed_tools: tuple[ToolDescriptor, ...]
    observed_disabled_tools: tuple[str, ...]
    extra_tools: tuple[str, ...]
    enabled_tools: tuple[str, ...]
    models: tuple[MeshModel, ...]
    call_remote_tool_invocation_enabled: bool
    mesh_ready: bool
    node_metadata: Mapping[str, Any]


def compatibility_status(value: str) -> ProbeStatus:
    mapping = {
        "supported": ProbeStatus.VERIFIED_NOW,
        "live": ProbeStatus.VERIFIED_NOW,
        "missing": ProbeStatus.UNSUPPORTED,
        "schema_mismatch": ProbeStatus.SCHEMA_CHANGED,
        "transport_failure": ProbeStatus.UNREACHABLE,
        "mixed": ProbeStatus.PARTIAL,
        "prior_reused": ProbeStatus.CACHED,
    }
    try:
        return mapping[value]
    except KeyError as exc:
        raise ValueError(f"unknown compatibility status: {value}") from exc


def _schema_matches(schema: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    if schema.get("type") != "object":
        return False
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        return False
    required = schema.get("required", [])
    if not isinstance(required, (list, tuple)) or not all(
        isinstance(item, str) for item in required
    ):
        return False
    if set(required) != set(expected["required"]):
        return False
    expected_properties = expected["properties"]
    if set(properties) != set(expected_properties):
        return False
    for name, expected_type in expected_properties.items():
        value = properties.get(name)
        if not isinstance(value, Mapping) or value.get("type") != expected_type:
            return False
    return True


def _call_schema_matches(schema: Mapping[str, Any]) -> bool:
    if schema.get("type") != "object":
        return False
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        return False
    arguments = properties.get("arguments")
    labels = properties.get("required_labels")
    return (
        isinstance(arguments, Mapping)
        and arguments.get("type") == "object"
        and isinstance(labels, Mapping)
        and labels.get("type") == "string"
    )


def _aggregate_status(features: Mapping[str, FeatureProbe]) -> ProbeStatus:
    statuses = {feature.status for feature in features.values()}
    if statuses == {ProbeStatus.VERIFIED_NOW}:
        return ProbeStatus.VERIFIED_NOW
    if statuses == {ProbeStatus.UNREACHABLE}:
        return ProbeStatus.UNREACHABLE
    if statuses == {ProbeStatus.CACHED}:
        return ProbeStatus.CACHED
    return ProbeStatus.PARTIAL


class CapabilityProbe:
    """Probe observable capabilities without inferring support from versions."""

    def __init__(self, client: SamClient) -> None:
        self._client = client

    async def probe(self) -> CompatibilityReport:
        features: dict[str, FeatureProbe] = {}
        metadata: dict[str, Any] = {}
        capabilities: McpCapabilities | None = None
        tools: tuple[ToolDescriptor, ...] = ()
        models: tuple[MeshModel, ...] = ()
        mesh_ready = False

        try:
            health = await self._client.health()
            metadata["healthz"] = dict(health.payload)
            features["healthz"] = FeatureProbe(
                ProbeStatus.VERIFIED_NOW if health.ready else ProbeStatus.PARTIAL
            )
        except SamError as exc:
            features["healthz"] = self._failed_probe(exc)

        try:
            readiness = await self._client.readiness()
            metadata["readyz"] = dict(readiness.payload)
            features["readyz"] = FeatureProbe(
                ProbeStatus.VERIFIED_NOW if readiness.ready else ProbeStatus.PARTIAL
            )
            mesh_ready = readiness.payload.get("mesh_ready") is True
        except SamError as exc:
            features["readyz"] = self._failed_probe(exc)

        try:
            capabilities = await self._client.initialize_mcp()
            features["mcp_initialize"] = FeatureProbe(ProbeStatus.VERIFIED_NOW)
        except SamError as exc:
            features["mcp_initialize"] = self._failed_probe(exc)

        if capabilities is not None:
            try:
                tools = await self._client.list_tools()
                features["tools_list"] = FeatureProbe(ProbeStatus.VERIFIED_NOW)
            except SamError as exc:
                features["tools_list"] = self._failed_probe(exc)
        else:
            features["tools_list"] = FeatureProbe(
                ProbeStatus.UNREACHABLE,
                "tools/list requires a successful MCP initialization",
            )

        by_name = {tool.canonical_uri.rsplit("/", 1)[-1]: tool for tool in tools}
        tools_list_status = features["tools_list"].status
        missing_tool_status = (
            ProbeStatus.UNSUPPORTED
            if tools_list_status is ProbeStatus.VERIFIED_NOW
            else tools_list_status
        )
        enabled_tools: list[str] = []
        for name, expected_schema in EXPECTED_READ_TOOL_SCHEMAS.items():
            descriptor = by_name.get(name)
            if descriptor is None:
                features[f"tool:{name}"] = FeatureProbe(missing_tool_status)
            elif _schema_matches(descriptor.input_schema, expected_schema):
                features[f"tool:{name}"] = FeatureProbe(ProbeStatus.VERIFIED_NOW)
                enabled_tools.append(name)
            else:
                features[f"tool:{name}"] = FeatureProbe(ProbeStatus.SCHEMA_CHANGED)

        for name in REMOVED_DIAGNOSTIC_TOOLS:
            observed = name in by_name
            if observed:
                status = ProbeStatus.UNSUPPORTED
                detail = "legacy diagnostic observed but disabled as a model tool"
            else:
                status = missing_tool_status
                detail = (
                    "diagnostic is absent and unsupported"
                    if status is ProbeStatus.UNSUPPORTED
                    else "diagnostic availability could not be observed"
                )
            features[f"tool:{name}"] = FeatureProbe(status, detail)

        call_descriptor = by_name.get("call_remote_tool")
        call_enabled = False
        if call_descriptor is None:
            features["tool:call_remote_tool"] = FeatureProbe(missing_tool_status)
        elif _call_schema_matches(call_descriptor.input_schema):
            features["tool:call_remote_tool"] = FeatureProbe(ProbeStatus.VERIFIED_NOW)
            call_enabled = True
        else:
            features["tool:call_remote_tool"] = FeatureProbe(ProbeStatus.SCHEMA_CHANGED)

        try:
            models = await self._client.list_models()
            features["models"] = FeatureProbe(ProbeStatus.VERIFIED_NOW)
        except SamError as exc:
            features["models"] = self._failed_probe(exc)

        observed_names = tuple(by_name)
        observed_disabled = tuple(name for name in observed_names if name not in enabled_tools)
        extra_tools = tuple(name for name in observed_names if name not in _KNOWN_CURRENT_TOOLS)
        return CompatibilityReport(
            status=_aggregate_status(features),
            server_name=None if capabilities is None else capabilities.server_name,
            server_version=None if capabilities is None else capabilities.server_version,
            protocol_version=None if capabilities is None else capabilities.protocol_version,
            features=MappingProxyType(features),
            observed_tools=tuple(tools),
            observed_disabled_tools=observed_disabled,
            extra_tools=extra_tools,
            enabled_tools=tuple(enabled_tools),
            models=tuple(models),
            call_remote_tool_invocation_enabled=call_enabled,
            mesh_ready=mesh_ready,
            node_metadata=MappingProxyType(metadata),
        )

    @staticmethod
    def _failed_probe(error: SamError) -> FeatureProbe:
        status = (
            ProbeStatus.UNREACHABLE
            if isinstance(error, SamConnectivityError)
            else ProbeStatus.SCHEMA_CHANGED
            if isinstance(error, SamSchemaError)
            else ProbeStatus.UNSUPPORTED
            if isinstance(error, SamProviderError) and error.status_code == 404
            else ProbeStatus.PARTIAL
        )
        return FeatureProbe(status=status, detail=type(error).__name__)
