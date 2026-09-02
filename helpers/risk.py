"""Deterministic, conservative risk classification for discovered SAM tools."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from .domain import RiskLevel, ToolDescriptor


@dataclass(frozen=True)
class RiskAssessment:
    """Stable classification data consumed by route cards, leases, and the gate."""

    level: RiskLevel
    requires_single_use_lease: bool
    reasons: tuple[str, ...]
    evidence: tuple[str, ...]


_RISK_PRECEDENCE = (
    RiskLevel.DESTRUCTIVE,
    RiskLevel.FINANCIAL,
    RiskLevel.CREDENTIAL,
    RiskLevel.MUTATION,
    RiskLevel.NETWORK,
    RiskLevel.READ_ONLY,
)
_SINGLE_USE_LEVELS = {
    RiskLevel.DESTRUCTIVE,
    RiskLevel.FINANCIAL,
    RiskLevel.CREDENTIAL,
    RiskLevel.MUTATION,
    RiskLevel.UNKNOWN,
}
_RULES: dict[RiskLevel, tuple[tuple[str, str], ...]] = {
    RiskLevel.DESTRUCTIVE: (
        ("delete", "delete"),
        ("drop", "drop"),
        ("erase", "erase"),
        ("destroy", "destroy"),
        ("remove", "remove"),
        ("revoke", "revoke"),
    ),
    RiskLevel.FINANCIAL: (
        ("purchase", "purchase"),
        ("payment", "payment"),
        ("pay", "pay"),
        ("amount", "amount"),
        ("price", "price"),
        ("invoice", "invoice"),
        ("transfer", "transfer"),
    ),
    RiskLevel.CREDENTIAL: (
        ("token", "token"),
        ("secret", "secret"),
        ("password", "password"),
        ("credential", "credential"),
        ("authorization", "authorization"),
        ("cookie", "cookie"),
        ("api_key", "api_key"),
        ("apikey", "apikey"),
    ),
    RiskLevel.MUTATION: (
        ("create", "create"),
        ("update", "update"),
        ("write", "write"),
        ("send", "send"),
        ("publish", "publish"),
        ("set", "set"),
        ("put", "put"),
        ("patch", "patch"),
        ("upload", "upload"),
    ),
    RiskLevel.NETWORK: (
        ("network", "network"),
        ("connect", "connect"),
        ("fetch", "fetch"),
        ("request", "request"),
        ("url", "url"),
        ("uri", "uri"),
        ("host", "host"),
        ("endpoint", "endpoint"),
        ("socket", "socket"),
        ("path", "path"),
        ("file", "file"),
    ),
    RiskLevel.READ_ONLY: (
        ("list", "list"),
        ("get", "get"),
        ("find", "find"),
        ("search", "search"),
        ("describe", "describe"),
        ("status", "status"),
        ("health", "health"),
        ("read", "read"),
        ("view", "view"),
        ("inspect", "inspect"),
        ("query", "query"),
    ),
}
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _tokens(name: str) -> tuple[str, ...]:
    separated = _CAMEL_BOUNDARY_RE.sub(" ", name)
    return tuple(_TOKEN_RE.findall(separated.casefold()))


def _contains_rule(name_tokens: tuple[str, ...], rule: str) -> bool:
    rule_tokens = tuple(_TOKEN_RE.findall(rule.casefold()))
    width = len(rule_tokens)
    return any(
        name_tokens[index : index + width] == rule_tokens
        for index in range(len(name_tokens) - width + 1)
    )


def _match_name(
    source: str,
    path: str,
    name: str,
    *,
    include_read_only: bool,
) -> list[tuple[RiskLevel, str]]:
    name_tokens = _tokens(name)
    matches: list[tuple[RiskLevel, str]] = []
    for level in _RISK_PRECEDENCE:
        if level is RiskLevel.READ_ONLY and not include_read_only:
            continue
        for token, rule_id in _RULES[level]:
            if _contains_rule(name_tokens, token):
                matches.append((level, f"{source}:{path}:{level.value}.{rule_id}"))
    return matches


def _mapping_key_matches(
    value: Mapping[str, Any], source: str, path: str
) -> list[tuple[RiskLevel, str]]:
    matches: list[tuple[RiskLevel, str]] = []
    for key in sorted(value, key=lambda item: (item.casefold(), item)):
        key_path = f"{path}.{key}"
        matches.extend(_match_name(source, key_path, key, include_read_only=False))
        nested = value[key]
        if isinstance(nested, Mapping):
            matches.extend(_mapping_key_matches(nested, source, key_path))
        elif isinstance(nested, (list, tuple)):
            matches.extend(_sequence_key_matches(nested, source, key_path))
    return matches


def _sequence_key_matches(
    value: list[Any] | tuple[Any, ...], source: str, path: str
) -> list[tuple[RiskLevel, str]]:
    matches: list[tuple[RiskLevel, str]] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if isinstance(item, Mapping):
            matches.extend(_mapping_key_matches(item, source, item_path))
        elif isinstance(item, (list, tuple)):
            matches.extend(_sequence_key_matches(item, source, item_path))
    return matches


def _annotation_matches(annotations: Mapping[str, Any]) -> list[tuple[RiskLevel, str]]:
    """Use only annotation states that can preserve or increase risk."""
    matches: list[tuple[RiskLevel, str]] = []
    if annotations.get("destructiveHint") is True:
        matches.append((RiskLevel.DESTRUCTIVE, "annotation:destructiveHint:true"))
    if annotations.get("readOnlyHint") is False:
        matches.append((RiskLevel.MUTATION, "annotation:readOnlyHint:false"))
    if annotations.get("openWorldHint") is True:
        matches.append((RiskLevel.NETWORK, "annotation:openWorldHint:true"))
    return matches


def classify(descriptor: ToolDescriptor, arguments: Mapping[str, Any]) -> RiskAssessment:
    """Classify from safe identity/key evidence without inspecting argument values."""
    if not isinstance(arguments, Mapping):
        raise TypeError("arguments must be a mapping")

    matches = _match_name(
        "identity",
        "canonical_uri",
        descriptor.canonical_uri,
        include_read_only=True,
    )
    matches.extend(_mapping_key_matches(descriptor.input_schema, "schema", "input_schema"))
    matches.extend(_mapping_key_matches(arguments, "argument", "arguments"))
    matches.extend(_annotation_matches(descriptor.annotations))

    evidence_by_level: dict[RiskLevel, set[str]] = {
        level: set() for level in _RISK_PRECEDENCE
    }
    for level, evidence in matches:
        evidence_by_level[level].add(evidence)

    level = next(
        (candidate for candidate in _RISK_PRECEDENCE if evidence_by_level[candidate]),
        RiskLevel.UNKNOWN,
    )
    evidence = tuple(sorted({item for items in evidence_by_level.values() for item in items}))
    reasons = (
        ("no_trusted_risk_evidence",)
        if level is RiskLevel.UNKNOWN
        else (f"classified_{level.value}",)
    )
    return RiskAssessment(
        level=level,
        requires_single_use_lease=level in _SINGLE_USE_LEVELS,
        reasons=reasons,
        evidence=evidence,
    )
