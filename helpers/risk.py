"""Deterministic, conservative risk classification for discovered SAM tools."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit

from .domain import RiskLevel, ToolDescriptor


@dataclass(frozen=True)
class RiskAssessment:
    """Stable classification data consumed by route cards, leases, and the gate."""

    level: RiskLevel
    requires_single_use_lease: bool
    reasons: tuple[str, ...]
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        expected = self.level in _SINGLE_USE_LEVELS
        if self.requires_single_use_lease is not expected:
            raise ValueError("requires_single_use_lease is inconsistent with risk level")
        if not isinstance(self.reasons, tuple) or not isinstance(self.evidence, tuple):
            raise TypeError("risk reasons and evidence must be immutable tuples")


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
_RULES: dict[RiskLevel, tuple[tuple[tuple[str, ...], str], ...]] = {
    RiskLevel.DESTRUCTIVE: (
        (("delete", "deletes", "deleted", "deleting"), "delete"),
        (("drop", "drops", "dropped", "dropping"), "drop"),
        (("erase", "erases", "erased", "erasing"), "erase"),
        (("destroy", "destroys", "destroyed", "destroying"), "destroy"),
        (("remove", "removes", "removed", "removing"), "remove"),
        (("revoke", "revokes", "revoked", "revoking"), "revoke"),
    ),
    RiskLevel.FINANCIAL: (
        (("purchase", "purchases", "purchased", "purchasing"), "purchase"),
        (("payment", "payments"), "payment"),
        (("pay", "pays", "paid", "paying"), "pay"),
        (("amount", "amounts"), "amount"),
        (("price", "prices", "priced", "pricing"), "price"),
        (("invoice", "invoices", "invoiced", "invoicing"), "invoice"),
        (("transfer", "transfers", "transferred", "transferring"), "transfer"),
    ),
    RiskLevel.CREDENTIAL: (
        (("token", "tokens"), "token"),
        (("secret", "secrets"), "secret"),
        (("password", "passwords"), "password"),
        (("credential", "credentials"), "credential"),
        (("authorization", "authorizations"), "authorization"),
        (("cookie", "cookies"), "cookie"),
        (("api key", "api keys"), "api_key"),
        (("apikey", "apikeys"), "apikey"),
    ),
    RiskLevel.MUTATION: (
        (("create", "creates", "created", "creating"), "create"),
        (("update", "updates", "updated", "updating"), "update"),
        (("write", "writes", "wrote", "written", "writing"), "write"),
        (("send", "sends", "sent", "sending"), "send"),
        (("publish", "publishes", "published", "publishing"), "publish"),
        (("set", "sets", "setting"), "set"),
        (("put", "puts", "putting"), "put"),
        (("patch", "patches", "patched", "patching"), "patch"),
        (("upload", "uploads", "uploaded", "uploading"), "upload"),
    ),
    RiskLevel.NETWORK: (
        (("network", "networks"), "network"),
        (("connect", "connects", "connected", "connecting"), "connect"),
        (("fetch", "fetches", "fetched", "fetching"), "fetch"),
        (("request", "requests", "requested", "requesting"), "request"),
        (("url", "urls"), "url"),
        (("uri", "uris"), "uri"),
        (("host", "hosts"), "host"),
        (("endpoint", "endpoints"), "endpoint"),
        (("socket", "sockets"), "socket"),
        (("path", "paths"), "path"),
        (("file", "files"), "file"),
    ),
    RiskLevel.READ_ONLY: (
        (("list", "lists", "listing"), "list"),
        (("get", "gets", "getting"), "get"),
        (("find", "finds", "finding"), "find"),
        (("search", "searches", "searched", "searching"), "search"),
        (("describe", "describes", "described", "describing"), "describe"),
        (("status", "statuses"), "status"),
        (("health",), "health"),
        (("read", "reads", "reading"), "read"),
        (("view", "views", "viewed", "viewing"), "view"),
        (("inspect", "inspects", "inspected", "inspecting"), "inspect"),
        (("query", "queries", "queried", "querying"), "query"),
    ),
}
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _tokens(name: str) -> tuple[str, ...]:
    separated = _CAMEL_BOUNDARY_RE.sub(" ", name)
    return tuple(_TOKEN_RE.findall(separated.casefold()))


def _contains_variant(name_tokens: tuple[str, ...], variant: str) -> bool:
    variant_tokens = tuple(_TOKEN_RE.findall(variant.casefold()))
    width = len(variant_tokens)
    return any(
        name_tokens[index : index + width] == variant_tokens
        for index in range(len(name_tokens) - width + 1)
    )


def _match_name(
    source: str,
    name: str,
    *,
    source_id: str = "",
    include_read_only: bool,
) -> list[tuple[RiskLevel, str]]:
    name_tokens = _tokens(name)
    matches: list[tuple[RiskLevel, str]] = []
    location = f":{source_id}" if source_id else ""
    for level in _RISK_PRECEDENCE:
        if level is RiskLevel.READ_ONLY and not include_read_only:
            continue
        for variants, rule_id in _RULES[level]:
            if any(_contains_variant(name_tokens, variant) for variant in variants):
                matches.append((level, f"{source}{location}:{level.value}.{rule_id}"))
    return matches


def _safe_source_id(path: tuple[str, ...]) -> str:
    canonical = "\x00".join(path).encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(canonical).hexdigest()[:16]


def _mapping_key_matches(
    value: Mapping[str, Any],
    source: str,
    path: tuple[str, ...],
) -> list[tuple[RiskLevel, str]]:
    matches: list[tuple[RiskLevel, str]] = []
    for key in sorted(value, key=lambda item: (item.casefold(), item)):
        key_path = path + (key,)
        matches.extend(
            _match_name(
                f"{source}:key",
                key,
                source_id=_safe_source_id(key_path),
                include_read_only=False,
            )
        )
        nested = value[key]
        if isinstance(nested, Mapping):
            matches.extend(_mapping_key_matches(nested, source, key_path))
        elif isinstance(nested, (list, tuple)):
            matches.extend(_sequence_key_matches(nested, source, key_path))
    return matches


def _sequence_key_matches(
    value: list[Any] | tuple[Any, ...],
    source: str,
    path: tuple[str, ...],
) -> list[tuple[RiskLevel, str]]:
    matches: list[tuple[RiskLevel, str]] = []
    for index, item in enumerate(value):
        item_path = path + (f"[{index}]",)
        if isinstance(item, Mapping):
            matches.extend(_mapping_key_matches(item, source, item_path))
        elif isinstance(item, (list, tuple)):
            matches.extend(_sequence_key_matches(item, source, item_path))
    return matches


def _tool_identity(canonical_uri: str) -> str:
    if canonical_uri.startswith("mcp://"):
        parsed = urlsplit(canonical_uri)
        if parsed.scheme == "mcp" and parsed.netloc and parsed.path.strip("/"):
            return parsed.path.strip("/")
        return ""
    return canonical_uri if "/" not in canonical_uri else ""


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
        "identity:tool",
        _tool_identity(descriptor.canonical_uri),
        include_read_only=True,
    )
    matches.extend(_mapping_key_matches(descriptor.input_schema, "schema", ()))
    matches.extend(_mapping_key_matches(arguments, "argument", ()))
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
