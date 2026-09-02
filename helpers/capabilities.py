"""Runtime capability and exact SAM schema probes."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from .domain import MeshModel, ProbeStatus
from .mcp_transport import (
    SamConnectivityError,
    SamError,
    SamProviderError,
    SamSchemaError,
)
from .sam_client import McpCapabilities, McpTool, SamClient

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
CALL_REMOTE_TOOL_SCHEMA: Mapping[str, Any] = MappingProxyType(
    {
        "properties": MappingProxyType(
            {
                "peer_id": "string",
                "tool_name": "string",
                "arguments": "object",
                "required_labels": "string",
            }
        ),
        "required": ("peer_id", "tool_name"),
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


def _freeze_json(value: Any, path: str) -> Any:
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
    observed_tools: tuple[McpTool, ...]
    observed_disabled_tools: tuple[str, ...]
    extra_tools: tuple[str, ...]
    enabled_tools: tuple[str, ...]
    models: tuple[MeshModel, ...]
    call_remote_tool_schema_compatible: bool
    call_remote_tool_invocation_enabled: bool
    mesh_ready: bool
    node_metadata: Mapping[str, Any]

    def __post_init__(self) -> None:
        features = MappingProxyType(dict(self.features))
        metadata = _freeze_json(self.node_metadata, "node metadata")
        object.__setattr__(self, "features", features)
        object.__setattr__(self, "node_metadata", metadata)
        object.__setattr__(self, "observed_tools", tuple(self.observed_tools))
        object.__setattr__(
            self,
            "observed_disabled_tools",
            tuple(self.observed_disabled_tools),
        )
        object.__setattr__(self, "extra_tools", tuple(self.extra_tools))
        object.__setattr__(self, "enabled_tools", tuple(self.enabled_tools))
        object.__setattr__(self, "models", tuple(self.models))


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
    if len(required) != len(set(required)) or set(required) != set(expected["required"]):
        return False
    expected_properties = expected["properties"]
    if set(properties) != set(expected_properties):
        return False
    for name, expected_type in expected_properties.items():
        value = properties.get(name)
        if not isinstance(value, Mapping) or value.get("type") != expected_type:
            return False
    additional = schema.get("additionalProperties")
    return additional is None or additional is False


def _tool_probe_name(tool: McpTool) -> str:
    if tool.canonical_uri is None:
        return tool.wire_name
    parsed = urlsplit(tool.canonical_uri)
    return parsed.path.rstrip("/").rsplit("/", 1)[-1]


def _index_tools(tools: list[McpTool]) -> tuple[dict[str, McpTool], set[str]]:
    indexed: dict[str, McpTool] = {}
    duplicates: set[str] = set()
    for tool in tools:
        name = _tool_probe_name(tool)
        if name in indexed:
            duplicates.add(name)
        else:
            indexed[name] = tool
    for name in duplicates:
        indexed.pop(name, None)
    return indexed, duplicates


def _aggregate_status(
    features: Mapping[str, FeatureProbe],
    required_features: tuple[str, ...],
) -> ProbeStatus:
    statuses = {features[name].status for name in required_features}
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
        tools: list[McpTool] = []
        models: list[MeshModel] = []
        mesh_ready = False

        try:
            health = await self._client.health()
            metadata["healthz"] = health.payload
            features["healthz"] = FeatureProbe(
                ProbeStatus.VERIFIED_NOW if health.ready else ProbeStatus.PARTIAL
            )
        except SamError as exc:
            features["healthz"] = self._failed_probe(exc)

        try:
            readiness = await self._client.readiness()
            metadata["readyz"] = readiness.payload
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
            dependency = features["mcp_initialize"]
            features["tools_list"] = FeatureProbe(
                dependency.status,
                f"depends on initialize: {dependency.detail}",
            )

        by_name, duplicate_names = _index_tools(tools)
        tools_list_status = features["tools_list"].status
        missing_tool_status = (
            ProbeStatus.UNSUPPORTED
            if tools_list_status is ProbeStatus.VERIFIED_NOW
            else tools_list_status
        )
        enabled_tools: list[str] = []
        required_feature_names = ["healthz", "readyz", "mcp_initialize", "tools_list"]
        for name, expected_schema in EXPECTED_READ_TOOL_SCHEMAS.items():
            feature_name = f"tool:{name}"
            required_feature_names.append(feature_name)
            descriptor = by_name.get(name)
            if name in duplicate_names:
                features[feature_name] = FeatureProbe(
                    ProbeStatus.SCHEMA_CHANGED,
                    "multiple tools resolve to the same probe name",
                )
            elif descriptor is None:
                features[feature_name] = FeatureProbe(missing_tool_status)
            elif _schema_matches(descriptor.input_schema, expected_schema):
                features[feature_name] = FeatureProbe(ProbeStatus.VERIFIED_NOW)
                enabled_tools.append(name)
            else:
                features[feature_name] = FeatureProbe(ProbeStatus.SCHEMA_CHANGED)

        for name in REMOVED_DIAGNOSTIC_TOOLS:
            observed = name in by_name
            if observed:
                status = ProbeStatus.UNSUPPORTED
                detail = "legacy diagnostic observed but disabled as a model tool"
            elif tools_list_status is ProbeStatus.VERIFIED_NOW:
                status = ProbeStatus.UNSUPPORTED
                detail = "diagnostic is absent and unsupported"
            else:
                status = tools_list_status
                detail = "diagnostic availability could not be observed"
            features[f"tool:{name}"] = FeatureProbe(status, detail)

        call_descriptor = by_name.get("call_remote_tool")
        call_compatible = False
        call_feature = "tool:call_remote_tool"
        required_feature_names.append(call_feature)
        if "call_remote_tool" in duplicate_names:
            features[call_feature] = FeatureProbe(
                ProbeStatus.SCHEMA_CHANGED,
                "multiple call_remote_tool identities were observed",
            )
        elif call_descriptor is None:
            features[call_feature] = FeatureProbe(missing_tool_status)
        elif _schema_matches(call_descriptor.input_schema, CALL_REMOTE_TOOL_SCHEMA):
            features[call_feature] = FeatureProbe(ProbeStatus.VERIFIED_NOW)
            call_compatible = True
        else:
            features[call_feature] = FeatureProbe(ProbeStatus.SCHEMA_CHANGED)

        try:
            models = await self._client.list_models()
            features["models"] = FeatureProbe(ProbeStatus.VERIFIED_NOW)
        except SamError as exc:
            features["models"] = self._failed_probe(exc)
        required_feature_names.append("models")

        observed_disabled = tuple(
            tool.wire_name
            for tool in tools
            if _tool_probe_name(tool) not in enabled_tools
        )
        extra_tools = tuple(
            tool.wire_name
            for tool in tools
            if _tool_probe_name(tool) not in _KNOWN_CURRENT_TOOLS
        )
        return CompatibilityReport(
            status=_aggregate_status(features, tuple(required_feature_names)),
            server_name=None if capabilities is None else capabilities.server_name,
            server_version=None if capabilities is None else capabilities.server_version,
            protocol_version=None if capabilities is None else capabilities.protocol_version,
            features=features,
            observed_tools=tuple(tools),
            observed_disabled_tools=observed_disabled,
            extra_tools=extra_tools,
            enabled_tools=tuple(enabled_tools),
            models=tuple(models),
            call_remote_tool_schema_compatible=call_compatible,
            call_remote_tool_invocation_enabled=False,
            mesh_ready=mesh_ready,
            node_metadata=metadata,
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
