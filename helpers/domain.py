"""Frozen domain records shared by the SAM Mesh Embassy tracks."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal, Mapping


def _freeze_json(value: Any, path: str = "schema") -> Any:
    """Copy JSON data into recursively immutable containers."""
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} must contain only JSON object keys")
            frozen[key] = _freeze_json(item, f"{path}.{key}")
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item, f"{path}[]") for item in value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise TypeError(f"{path} must contain only finite JSON values")


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_json(item) for item in value]
    return value


def validate_required_label(value: object) -> str:
    """Validate one exact SAM key=value label without normalizing wire identity."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("required labels must be exact nonempty key=value strings")
    if value.count("=") != 1 or "," in value:
        raise ValueError("required labels must be exact nonempty key=value strings")
    key, label_value = value.split("=", 1)
    if (
        not key
        or not label_value
        or key != key.strip()
        or label_value != label_value.strip()
    ):
        raise ValueError("required labels must be exact nonempty key=value strings")
    return value


def _tool_schema_hash(
    input_schema: Mapping[str, Any], output_schema: Mapping[str, Any] | None
) -> str:
    canonical = json.dumps(
        {
            "input_schema": _plain_json(input_schema),
            "output_schema": _plain_json(output_schema),
        },
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class OperatingMode(StrEnum):
    EXPLORER = "explorer"
    GUARDED_MESH = "guarded_mesh"
    RAW_MCP = "raw_mcp"
    EMBASSY = "embassy"
    SOVEREIGN = "sovereign"


class DataClass(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    REGULATED = "regulated"


class RiskLevel(StrEnum):
    READ_ONLY = "read_only"
    NETWORK = "network"
    MUTATION = "mutation"
    DESTRUCTIVE = "destructive"
    FINANCIAL = "financial"
    CREDENTIAL = "credential"
    UNKNOWN = "unknown"


class RouteMode(StrEnum):
    AUTOMATIC = "automatic"
    PINNED = "pinned"


class ProbeStatus(StrEnum):
    VERIFIED_NOW = "verified_now"
    CACHED = "cached"
    PARTIAL = "partial"
    UNREACHABLE = "unreachable"
    SCHEMA_CHANGED = "schema_changed"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class Scope:
    """Agent Zero scope that later approval leases must bind exactly."""

    project_name: str
    agent_profile: str
    chat_id: str


@dataclass(frozen=True)
class TransportConfig:
    type: Literal["http", "uds"]
    base_url: str
    socket_path: str | None
    token: str | None = field(repr=False)
    allowed_origins: tuple[str, ...] = ()


@dataclass(frozen=True)
class OutboundPolicy:
    max_data_class: DataClass
    allow_services: tuple[str, ...]
    deny_tools: tuple[str, ...]
    remote_mutations: Literal["deny", "approval", "allow"]


@dataclass(frozen=True)
class InferencePolicy:
    enabled: bool
    route_mode: RouteMode
    required_labels: tuple[str, ...]
    sensitive_data: Literal["deny", "approval", "allow"]
    label_semantics: Literal["any_of"] = "any_of"


@dataclass(frozen=True)
class PassportLimits:
    calls_per_session: int
    discovery_timeout_seconds: int
    timeout_seconds: int
    approval_lease_minutes: int


@dataclass(frozen=True)
class InboundPolicy:
    enabled: bool
    services: tuple[str, ...]


@dataclass(frozen=True)
class CapabilityPassport:
    schema: str
    mode: OperatingMode
    outbound: OutboundPolicy
    inference: InferencePolicy
    limits: PassportLimits
    inbound: InboundPolicy

    def to_dict(self) -> dict[str, Any]:
        """Return the stable JSON representation used for passport binding."""
        return {
            "schema": self.schema,
            "mode": self.mode.value,
            "outbound": {
                "max_data_class": self.outbound.max_data_class.value,
                "allow_services": list(self.outbound.allow_services),
                "deny_tools": list(self.outbound.deny_tools),
                "remote_mutations": self.outbound.remote_mutations,
            },
            "inference": {
                "enabled": self.inference.enabled,
                "route_mode": self.inference.route_mode.value,
                "required_labels": list(self.inference.required_labels),
                "sensitive_data": self.inference.sensitive_data,
                "label_semantics": self.inference.label_semantics,
            },
            "limits": {
                "calls_per_session": self.limits.calls_per_session,
                "discovery_timeout_seconds": self.limits.discovery_timeout_seconds,
                "timeout_seconds": self.limits.timeout_seconds,
                "approval_lease_minutes": self.limits.approval_lease_minutes,
            },
            "inbound": {
                "enabled": self.inbound.enabled,
                "services": list(self.inbound.services),
            },
        }

    def version_hash(self) -> str:
        canonical = json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True)
class FeatureFlags:
    remote_calls: bool
    mesh_inference: bool
    inbound_publication: bool
    raw_mcp: bool


@dataclass(frozen=True)
class ResolvedConfig:
    transport: TransportConfig
    passport: CapabilityPassport
    features: FeatureFlags
    scope: Scope


@dataclass(frozen=True)
class ToolDescriptor:
    canonical_uri: str
    peer_id: str
    service: str
    description: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any] | None
    labels: tuple[str, ...]
    discovered_at: str
    discovery_source: str
    schema_hash: str
    annotations: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        input_schema = _freeze_json(self.input_schema, "input_schema")
        if not isinstance(input_schema, Mapping):
            raise TypeError("input_schema must be a JSON object")
        output_schema = (
            None
            if self.output_schema is None
            else _freeze_json(self.output_schema, "output_schema")
        )
        if output_schema is not None and not isinstance(output_schema, Mapping):
            raise TypeError("output_schema must be a JSON object or null")
        annotations = _freeze_json(self.annotations, "annotations")
        if not isinstance(annotations, Mapping):
            raise TypeError("annotations must be a JSON object")
        expected_hash = _tool_schema_hash(input_schema, output_schema)
        if self.schema_hash != expected_hash:
            raise ValueError("schema_hash does not match the canonical frozen schemas")
        object.__setattr__(self, "input_schema", input_schema)
        object.__setattr__(self, "output_schema", output_schema)
        object.__setattr__(self, "annotations", annotations)

    def risk_metadata_hash(self) -> str:
        """Fingerprint immutable risk metadata separately from schema compatibility."""
        canonical = json.dumps(
            _plain_json(self.annotations),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True)
class MeshModel:
    """A model plus the discovered SAM provider identity, when available."""

    id: str
    owned_by: str
    peer_id: str | None
    service: str | None
    labels: tuple[str, ...]
    local_proxy_url: str | None
    discovered_at: str
    discovery_source: str


@dataclass(frozen=True)
class PreflightDecision:
    decision_id: str
    scope: Scope
    passport_version_hash: str
    destination_peer_id: str
    destination_service: str
    tool: ToolDescriptor
    classified_data_fields: tuple[str, ...]
    data_class: DataClass
    risk_level: RiskLevel
    risk_evidence: tuple[str, ...]
    route_mode: RouteMode
    required_labels: tuple[str, ...]
    duplicate_execution_possible: bool
    outcome: Literal["allow", "deny", "needs_approval"]
    reasons: tuple[str, ...]
    expires_at: str
