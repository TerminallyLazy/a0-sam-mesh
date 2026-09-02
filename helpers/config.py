"""Fail-closed scoped configuration resolution for the SAM Mesh plugin."""

from __future__ import annotations

import ipaddress
import os
import re
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .domain import (
    CapabilityPassport,
    DataClass,
    FeatureFlags,
    InboundPolicy,
    InferencePolicy,
    OperatingMode,
    OutboundPolicy,
    PassportLimits,
    ResolvedConfig,
    RouteMode,
    Scope,
    TransportConfig,
)

CONFIG_SCHEMA = "a0.sam.config/v1alpha1"
PASSPORT_SCHEMA = "a0.sam.passport/v1alpha1"
DEFAULT_ALLOWED_SOCKET_ROOTS = ("/var/run/sam", "/run/sam")
_SECRET_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ConfigError(ValueError):
    """Configuration was rejected before any SAM operation could occur."""


def _load_plugin_config(plugin_name: str, *, agent: Any) -> Any:
    from helpers.plugins import get_plugin_config

    return get_plugin_config(plugin_name, agent=agent)


def _load_secrets_manager(context: Any) -> Any:
    from helpers.secrets import get_secrets_manager

    return get_secrets_manager(context)


def _context_project_name(context: Any) -> str:
    try:
        from helpers.projects import get_context_project_name
    except ModuleNotFoundError:
        return str(getattr(context, "project_name", "") or "")
    return str(get_context_project_name(context) or "")


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigError(f"{path} must be an object")
    return value


def _reject_unknown(value: Mapping[str, Any], allowed: set[str], path: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ConfigError(f"{path} contains unknown keys: {', '.join(unknown)}")


def _required(value: Mapping[str, Any], key: str, path: str) -> Any:
    if key not in value:
        raise ConfigError(f"{path}.{key} is required")
    return value[key]


def _string(value: Any, path: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{path} must be a string")
    normalized = value.strip()
    if not allow_empty and not normalized:
        raise ConfigError(f"{path} must not be empty")
    return normalized


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{path} must be a boolean")
    return value


def _integer(value: Any, path: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ConfigError(f"{path} must be an integer >= {minimum}")
    return value


def _enum(enum_type: type, value: Any, path: str) -> Any:
    normalized = _string(value, path)
    try:
        return enum_type(normalized)
    except ValueError as exc:
        choices = ", ".join(member.value for member in enum_type)
        raise ConfigError(f"{path} must be one of: {choices}") from exc


def _choice(value: Any, choices: set[str], path: str) -> str:
    normalized = _string(value, path)
    if normalized not in choices:
        raise ConfigError(f"{path} must be one of: {', '.join(sorted(choices))}")
    return normalized


def _string_tuple(value: Any, path: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ConfigError(f"{path} must be an array of strings")
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        normalized = _string(item, f"{path}[{index}]")
        if normalized not in seen:
            result.append(normalized)
            seen.add(normalized)
    return tuple(result)


def _labels(value: Any, path: str) -> tuple[str, ...]:
    labels = _string_tuple(value, path)
    for label in labels:
        key, separator, label_value = label.partition("=")
        if not separator or not key.strip() or not label_value.strip() or "," in label:
            raise ConfigError(f"{path} entries must be exact key=value labels")
    return labels


def _normalize_base_url(value: Any, path: str = "transport.base_url") -> str:
    raw_url = _string(value, path)
    try:
        parsed = urlsplit(raw_url)
        port = parsed.port
    except ValueError as exc:
        raise ConfigError(f"{path} is invalid") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ConfigError(f"{path} must use http or https")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ConfigError(f"{path} must not contain userinfo and must have a host")
    if parsed.fragment or parsed.query:
        raise ConfigError(f"{path} must not contain a query or fragment")
    hostname = parsed.hostname.lower()
    if ":" in hostname:
        hostname = f"[{hostname}]"
    netloc = hostname if port is None else f"{hostname}:{port}"
    normalized_path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), netloc, normalized_path, "", ""))


def _url_origin(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _normalize_allowed_origins(value: Any) -> tuple[str, ...]:
    origins = _string_tuple(value, "transport.allowed_origins")
    normalized: list[str] = []
    for index, origin in enumerate(origins):
        path = f"transport.allowed_origins[{index}]"
        candidate = _normalize_base_url(origin, path)
        if urlsplit(candidate).path:
            raise ConfigError(f"{path} must be an origin without a path")
        if candidate not in normalized:
            normalized.append(candidate)
    return tuple(normalized)


def _validate_http_origin_policy(base_url: str, allowed_origins: tuple[str, ...]) -> None:
    """Apply syntactic SSRF policy; Task 3 must validate DNS and connected peers."""
    hostname = urlsplit(base_url).hostname
    assert hostname is not None
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None

    if address is not None:
        if address.is_loopback:
            return
        if (
            address.is_unspecified
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
        ):
            raise ConfigError("transport.base_url uses a dangerous literal IP class")
    elif hostname == "localhost":
        return

    if _url_origin(base_url) not in allowed_origins:
        raise ConfigError(
            "transport.base_url non-loopback host requires an explicit allowed origin"
        )


def _reject_relative_symlinks(socket_path: Path, allowed_root: Path) -> None:
    current = allowed_root
    for component in socket_path.relative_to(allowed_root).parts:
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ConfigError("transport.socket_path cannot be inspected safely") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ConfigError("transport.socket_path has a symlinked path component")


def _validate_socket_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISSOCK(metadata.st_mode):
        raise ConfigError("transport.socket_path must be a Unix socket")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise ConfigError(
            "transport.socket_path must be owned by root or the Agent Zero user"
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ConfigError("transport.socket_path must have safe permissions")


def _validate_existing_socket(
    socket_path: Path, allowed_root: Path, metadata: os.stat_result
) -> None:
    _validate_socket_metadata(metadata)
    flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(socket_path, flags)
    except OSError as exc:
        raise ConfigError("transport.socket_path changed during validation") from exc
    try:
        opened_metadata = os.fstat(descriptor)
        _reject_relative_symlinks(socket_path, allowed_root)
        if (opened_metadata.st_dev, opened_metadata.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            raise ConfigError("transport.socket_path changed during validation")
        _validate_socket_metadata(opened_metadata)
        current_metadata = socket_path.lstat()
        if (current_metadata.st_dev, current_metadata.st_ino) != (
            opened_metadata.st_dev,
            opened_metadata.st_ino,
        ):
            raise ConfigError("transport.socket_path changed during validation")
    except OSError as exc:
        raise ConfigError("transport.socket_path changed during validation") from exc
    finally:
        os.close(descriptor)


def _validate_socket_path(
    value: Any, allowed_roots: tuple[str, ...], *, allow_absent: bool
) -> str:
    raw_path = _string(value, "transport.socket_path")
    socket_path = Path(raw_path).expanduser()
    if not socket_path.is_absolute():
        raise ConfigError("transport.socket_path must be absolute")

    resolved = socket_path.resolve(strict=False)
    matching_root: Path | None = None
    for root in allowed_roots:
        candidate = Path(root).expanduser()
        if not candidate.is_absolute():
            raise ConfigError("allowed socket roots must be absolute")
        canonical_root = candidate.resolve(strict=False)
        if socket_path.is_relative_to(candidate) and resolved.is_relative_to(canonical_root):
            matching_root = candidate
            break
    if matching_root is None:
        raise ConfigError("transport.socket_path is outside allowed socket roots")

    _reject_relative_symlinks(socket_path, matching_root)
    try:
        metadata = socket_path.lstat()
    except FileNotFoundError:
        if not allow_absent:
            raise ConfigError(
                "transport.socket_path is absent while remote authority is enabled"
            )
        return str(resolved)
    except OSError as exc:
        raise ConfigError("transport.socket_path cannot be inspected safely") from exc
    _validate_existing_socket(socket_path, matching_root, metadata)
    return str(resolved)


def _resolve_secret_name(name: str, context: Any) -> str | None:
    if not name:
        return None
    if not _SECRET_NAME.fullmatch(name):
        raise ConfigError("transport.token_secret_name is not a valid secret name")
    secrets = _load_secrets_manager(context).load_secrets()
    token = secrets.get(name.upper())
    if not isinstance(token, str) or not token:
        raise ConfigError("transport.token_secret_name was not found")
    return token


def _validate_token_file_metadata(metadata: os.stat_result) -> None:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ConfigError("transport.token_file must be a regular file, not a symlink")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ConfigError("transport.token_file must have mode 0600")
    if metadata.st_uid != os.geteuid():
        raise ConfigError("transport.token_file must be owned by the Agent Zero user")


def _resolve_token_file(path: str) -> str | None:
    if not path:
        return None
    token_path = Path(path).expanduser()
    if not token_path.is_absolute():
        raise ConfigError("transport.token_file must be absolute")
    try:
        metadata = token_path.lstat()
    except OSError as exc:
        raise ConfigError("transport.token_file cannot be read") from exc
    _validate_token_file_metadata(metadata)

    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(token_path, flags)
    except OSError as exc:
        raise ConfigError("transport.token_file changed during validation") from exc
    try:
        opened_metadata = os.fstat(descriptor)
        if (opened_metadata.st_dev, opened_metadata.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            raise ConfigError("transport.token_file changed during validation")
        _validate_token_file_metadata(opened_metadata)
        with os.fdopen(descriptor, "rb", closefd=False) as token_stream:
            token_bytes = token_stream.read(65_537)
    finally:
        os.close(descriptor)

    if len(token_bytes) > 65_536:
        raise ConfigError("transport.token_file exceeds 64 KiB")
    try:
        token = token_bytes.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ConfigError("transport.token_file must contain UTF-8 text") from exc
    if not token:
        raise ConfigError("transport.token_file is empty")
    return token


def _parse_transport(
    value: Any,
    *,
    context: Any,
    allowed_socket_roots: tuple[str, ...],
    allow_absent_socket: bool,
) -> TransportConfig:
    transport = _mapping(value, "transport")
    if "token" in transport:
        raise ConfigError("transport must not contain a raw token")
    _reject_unknown(
        transport,
        {
            "type",
            "base_url",
            "socket_path",
            "token_secret_name",
            "token_file",
            "allowed_origins",
        },
        "transport",
    )
    transport_type = _choice(
        _required(transport, "type", "transport"),
        {"http", "uds"},
        "transport.type",
    )
    base_url = _normalize_base_url(_required(transport, "base_url", "transport"))
    allowed_origins = _normalize_allowed_origins(
        transport.get("allowed_origins", [])
    )
    socket_value = transport.get("socket_path")
    if transport_type == "uds":
        if allowed_origins:
            raise ConfigError("transport.allowed_origins is only valid for http transport")
        socket_path = _validate_socket_path(
            socket_value,
            allowed_socket_roots,
            allow_absent=allow_absent_socket,
        )
    else:
        if socket_value not in (None, ""):
            raise ConfigError("transport.socket_path is only valid for uds transport")
        socket_path = None
        _validate_http_origin_policy(base_url, allowed_origins)

    secret_name = _string(
        transport.get("token_secret_name", ""),
        "transport.token_secret_name",
        allow_empty=True,
    )
    token_file = _string(
        transport.get("token_file", ""), "transport.token_file", allow_empty=True
    )
    if secret_name and token_file:
        raise ConfigError("transport must configure exactly one credential source")
    token = (
        _resolve_secret_name(secret_name, context)
        if secret_name
        else _resolve_token_file(token_file)
    )
    return TransportConfig(
        type=transport_type,
        base_url=base_url,
        socket_path=socket_path,
        token=token,
        allowed_origins=allowed_origins,
    )


def _parse_passport(value: Any) -> CapabilityPassport:
    passport = _mapping(value, "passport")
    _reject_unknown(
        passport, {"schema", "mode", "outbound", "inference", "limits", "inbound"}, "passport"
    )
    schema = _string(_required(passport, "schema", "passport"), "passport.schema")
    if schema != PASSPORT_SCHEMA:
        raise ConfigError(f"passport.schema must be {PASSPORT_SCHEMA}")
    mode = _enum(OperatingMode, _required(passport, "mode", "passport"), "passport.mode")

    outbound = _mapping(_required(passport, "outbound", "passport"), "passport.outbound")
    _reject_unknown(
        outbound,
        {"max_data_class", "allow_services", "deny_tools", "remote_mutations"},
        "passport.outbound",
    )
    outbound_policy = OutboundPolicy(
        max_data_class=_enum(
            DataClass,
            _required(outbound, "max_data_class", "passport.outbound"),
            "passport.outbound.max_data_class",
        ),
        allow_services=_string_tuple(
            _required(outbound, "allow_services", "passport.outbound"),
            "passport.outbound.allow_services",
        ),
        deny_tools=_string_tuple(
            _required(outbound, "deny_tools", "passport.outbound"),
            "passport.outbound.deny_tools",
        ),
        remote_mutations=_choice(
            _required(outbound, "remote_mutations", "passport.outbound"),
            {"allow", "approval", "deny"},
            "passport.outbound.remote_mutations",
        ),
    )

    inference = _mapping(
        _required(passport, "inference", "passport"), "passport.inference"
    )
    _reject_unknown(
        inference,
        {"enabled", "route_mode", "required_labels", "sensitive_data"},
        "passport.inference",
    )
    inference_policy = InferencePolicy(
        enabled=_boolean(
            _required(inference, "enabled", "passport.inference"),
            "passport.inference.enabled",
        ),
        route_mode=_enum(
            RouteMode,
            _required(inference, "route_mode", "passport.inference"),
            "passport.inference.route_mode",
        ),
        required_labels=_labels(
            _required(inference, "required_labels", "passport.inference"),
            "passport.inference.required_labels",
        ),
        sensitive_data=_choice(
            _required(inference, "sensitive_data", "passport.inference"),
            {"allow", "approval", "deny"},
            "passport.inference.sensitive_data",
        ),
    )

    limits = _mapping(_required(passport, "limits", "passport"), "passport.limits")
    _reject_unknown(
        limits,
        {
            "calls_per_session",
            "discovery_timeout_seconds",
            "timeout_seconds",
            "approval_lease_minutes",
        },
        "passport.limits",
    )
    passport_limits = PassportLimits(
        calls_per_session=_integer(
            _required(limits, "calls_per_session", "passport.limits"),
            "passport.limits.calls_per_session",
            minimum=0,
        ),
        discovery_timeout_seconds=_integer(
            _required(limits, "discovery_timeout_seconds", "passport.limits"),
            "passport.limits.discovery_timeout_seconds",
            minimum=1,
        ),
        timeout_seconds=_integer(
            _required(limits, "timeout_seconds", "passport.limits"),
            "passport.limits.timeout_seconds",
            minimum=1,
        ),
        approval_lease_minutes=_integer(
            _required(limits, "approval_lease_minutes", "passport.limits"),
            "passport.limits.approval_lease_minutes",
            minimum=1,
        ),
    )

    inbound = _mapping(_required(passport, "inbound", "passport"), "passport.inbound")
    _reject_unknown(inbound, {"enabled", "services"}, "passport.inbound")
    inbound_policy = InboundPolicy(
        enabled=_boolean(
            _required(inbound, "enabled", "passport.inbound"),
            "passport.inbound.enabled",
        ),
        services=_string_tuple(
            _required(inbound, "services", "passport.inbound"),
            "passport.inbound.services",
        ),
    )
    return CapabilityPassport(
        schema=schema,
        mode=mode,
        outbound=outbound_policy,
        inference=inference_policy,
        limits=passport_limits,
        inbound=inbound_policy,
    )


def _parse_features(value: Any) -> FeatureFlags:
    features = _mapping(value, "features")
    _reject_unknown(
        features,
        {"remote_calls", "mesh_inference", "inbound_publication", "raw_mcp"},
        "features",
    )
    return FeatureFlags(
        remote_calls=_boolean(
            _required(features, "remote_calls", "features"), "features.remote_calls"
        ),
        mesh_inference=_boolean(
            _required(features, "mesh_inference", "features"),
            "features.mesh_inference",
        ),
        inbound_publication=_boolean(
            _required(features, "inbound_publication", "features"),
            "features.inbound_publication",
        ),
        raw_mcp=_boolean(
            _required(features, "raw_mcp", "features"), "features.raw_mcp"
        ),
    )


def _apply_mode_constraints(
    passport: CapabilityPassport, features: FeatureFlags
) -> tuple[CapabilityPassport, FeatureFlags]:
    mode = passport.mode
    inference_allowed = mode is not OperatingMode.EXPLORER
    inbound_allowed = mode in {OperatingMode.EMBASSY, OperatingMode.SOVEREIGN}
    raw_mcp_allowed = mode is OperatingMode.RAW_MCP
    remote_calls_allowed = mode is not OperatingMode.EXPLORER

    inference = InferencePolicy(
        enabled=passport.inference.enabled and inference_allowed,
        route_mode=passport.inference.route_mode,
        required_labels=passport.inference.required_labels,
        sensitive_data=passport.inference.sensitive_data,
        label_semantics=passport.inference.label_semantics,
    )
    inbound = InboundPolicy(
        enabled=passport.inbound.enabled and inbound_allowed,
        services=passport.inbound.services,
    )
    constrained_passport = CapabilityPassport(
        schema=passport.schema,
        mode=passport.mode,
        outbound=passport.outbound,
        inference=inference,
        limits=passport.limits,
        inbound=inbound,
    )
    constrained_features = FeatureFlags(
        remote_calls=features.remote_calls and remote_calls_allowed,
        mesh_inference=features.mesh_inference and inference.enabled,
        inbound_publication=features.inbound_publication and inbound.enabled,
        raw_mcp=features.raw_mcp and raw_mcp_allowed,
    )
    return constrained_passport, constrained_features


def _resolve_scope(agent: Any) -> Scope:
    context = getattr(agent, "context", None)
    if context is None:
        raise ConfigError("agent.context is required for scoped configuration")
    config = getattr(agent, "config", None)
    return Scope(
        project_name=_context_project_name(context),
        agent_profile=str(getattr(config, "profile", "") or ""),
        chat_id=str(getattr(context, "id", "") or ""),
    )


def resolve_config(
    agent: Any,
    *,
    raw: Mapping[str, Any] | None = None,
    allowed_socket_roots: tuple[str, ...] = DEFAULT_ALLOWED_SOCKET_ROOTS,
) -> ResolvedConfig:
    """Resolve scoped config, credentials, policy, and lease-relevant scope."""
    loaded = _load_plugin_config("sam_mesh", agent=agent) if raw is None else raw
    config = _mapping(loaded, "config")
    _reject_unknown(config, {"schema", "transport", "passport", "features"}, "config")
    schema = _string(_required(config, "schema", "config"), "config.schema")
    if schema != CONFIG_SCHEMA:
        raise ConfigError(f"config.schema must be {CONFIG_SCHEMA}")

    context = getattr(agent, "context", None)
    if context is None:
        raise ConfigError("agent.context is required for scoped configuration")
    passport = _parse_passport(_required(config, "passport", "config"))
    features = _parse_features(_required(config, "features", "config"))
    passport, features = _apply_mode_constraints(passport, features)
    authority_disabled = (
        passport.mode is OperatingMode.EXPLORER
        and not passport.inference.enabled
        and not passport.inbound.enabled
        and not any(
            (
                features.remote_calls,
                features.mesh_inference,
                features.inbound_publication,
                features.raw_mcp,
            )
        )
    )
    transport = _parse_transport(
        _required(config, "transport", "config"),
        context=context,
        allowed_socket_roots=allowed_socket_roots,
        allow_absent_socket=authority_disabled,
    )
    return ResolvedConfig(
        transport=transport,
        passport=passport,
        features=features,
        scope=_resolve_scope(agent),
    )
