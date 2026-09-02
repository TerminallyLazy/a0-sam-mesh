"""Frozen domain records shared by the SAM Mesh Embassy tracks."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal, Mapping


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
    token: str | None


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
