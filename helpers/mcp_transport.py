"""Bounded MCP Streamable HTTP transport for TCP and Unix sockets."""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import json
import socket
from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from .domain import TransportConfig

MCP_RESPONSE_MAX_BYTES = 4 * 1024 * 1024
MCP_PROTOCOL_VERSION = "2025-03-26"
MCP_PROTOCOL_VERSIONS = frozenset({MCP_PROTOCOL_VERSION})
Resolver = Callable[..., Awaitable[list[tuple[Any, ...]]]]


class SamError(RuntimeError):
    """Base for sanitized SAM adapter failures."""


class SamAuthRequired(SamError):
    """The SAM endpoint requires a credential."""


class SamAuthRejected(SamError):
    """The SAM endpoint rejected the resolved credential."""


class SamPolicyDenied(SamError):
    """SAM returned a machine-readable authorization or policy denial."""


class SamNodeNotReady(SamError):
    """The configured SAM node is not ready."""


class SamConnectivityError(SamError):
    """SAM connectivity failed with explicit dispatch-phase evidence."""

    def __init__(
        self,
        message: str,
        *,
        phase: str = "transport",
        dispatched: bool | None = None,
    ) -> None:
        super().__init__(message)
        self.phase = phase
        self.dispatched = dispatched


class SamCallAmbiguous(SamConnectivityError):
    """A tools/call may have executed before its response was lost."""

    duplicate_execution_possible = True


class SamSchemaError(SamError):
    """SAM returned malformed, oversized, or incompatible data."""


class SamProviderError(SamError):
    """SAM reached a provider or tool that returned a distinct failure."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname
    if not host:
        raise SamConnectivityError("SAM TCP endpoint has no host")
    rendered_host = f"[{host.lower()}]" if ":" in host else host.lower()
    default_port = 443 if scheme == "https" else 80
    netloc = (
        rendered_host
        if parsed.port in {None, default_port}
        else f"{rendered_host}:{parsed.port}"
    )
    return urlunsplit((scheme, netloc, "", "", ""))


def _address_is_forbidden(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        address.is_unspecified
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
    )


async def validate_tcp_origin(
    config: TransportConfig,
    *,
    resolver: Resolver | None = None,
) -> tuple[str, ...]:
    """Resolve every TCP address and reject origin drift and forbidden classes.

    This is a pre-connect guard. HTTPX does not expose a portable connected-peer
    address, so callers must not treat it as complete DNS-rebinding protection.
    """
    if config.type != "http":
        return ()
    parsed = urlsplit(config.base_url)
    host = parsed.hostname
    if not host:
        raise SamConnectivityError("SAM TCP endpoint has no host")
    origin = _origin(config.base_url)
    literal: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is None and host.lower() != "localhost":
        allowed = {_origin(value) for value in config.allowed_origins}
        if origin not in allowed:
            raise SamConnectivityError("SAM TCP origin is not exactly allowlisted")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        if resolver is None:
            results = await asyncio.get_running_loop().getaddrinfo(
                host,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        else:
            value = resolver(
                host,
                port,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
            )
            results = await value if inspect.isawaitable(value) else value
    except (OSError, asyncio.TimeoutError) as exc:
        raise SamConnectivityError("SAM TCP host resolution failed") from exc
    if not results:
        raise SamConnectivityError("SAM TCP host resolved to no addresses")

    addresses: list[str] = []
    for result in results:
        try:
            raw_address = result[4][0]
            address = ipaddress.ip_address(raw_address)
        except (IndexError, TypeError, ValueError) as exc:
            raise SamConnectivityError("SAM TCP host returned an invalid address") from exc
        configured_local = host.lower() == "localhost" or (
            literal is not None and literal.is_loopback
        )
        if address.is_loopback:
            if not configured_local:
                raise SamConnectivityError(
                    "SAM TCP host resolved to a forbidden address class"
                )
        elif _address_is_forbidden(address):
            raise SamConnectivityError("SAM TCP host resolved to a forbidden address class")
        rendered = str(address)
        if rendered not in addresses:
            addresses.append(rendered)
    return tuple(addresses)


def _machine_policy_denial(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    error = value.get("error", value)
    if not isinstance(error, Mapping):
        return False
    data = error.get("data")
    if not isinstance(data, Mapping):
        return False
    markers = {
        str(data.get("type", "")).lower(),
        str(data.get("code", "")).lower(),
        str(data.get("category", "")).lower(),
    }
    return bool(
        markers
        & {"policy_denied", "permission_denied", "authorization_denied"}
    )


def _decode_json_bytes(body: bytes) -> Any:
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SamSchemaError("SAM returned malformed JSON") from exc


def _decode_sse_bytes(body: bytes) -> list[Any]:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SamSchemaError("SAM returned malformed event-stream text") from exc
    events: list[Any] = []
    data_lines: list[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line == "":
            if data_lines:
                events.append(_decode_json_bytes("\n".join(data_lines).encode("utf-8")))
                data_lines = []
            continue
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "data":
            data_lines.append(value)
    if data_lines:
        events.append(_decode_json_bytes("\n".join(data_lines).encode("utf-8")))
    if not events:
        raise SamSchemaError("SAM event stream contained no data events")
    return events


class McpStreamableSession:
    """One MCP Streamable HTTP session with no automatic request replay."""

    def __init__(
        self,
        config: TransportConfig,
        *,
        timeout_seconds: float = 30.0,
        resolver: Resolver | None = None,
    ) -> None:
        if config.type == "uds" and not config.socket_path:
            raise SamSchemaError("SAM UDS transport requires a socket path")
        self._config = config
        self._resolver = resolver
        self._session_id: str | None = None
        self._protocol_version: str | None = None
        self._next_id = 1
        transport = (
            httpx.AsyncHTTPTransport(uds=config.socket_path, retries=0)
            if config.type == "uds"
            else httpx.AsyncHTTPTransport(retries=0)
        )
        timeout = httpx.Timeout(
            timeout_seconds,
            connect=timeout_seconds,
            read=timeout_seconds,
            write=timeout_seconds,
            pool=timeout_seconds,
        )
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if config.type == "http" and config.token:
            headers["X-Sam-Authentication"] = f"Bearer {config.token}"
        self._client = httpx.AsyncClient(
            base_url=config.base_url,
            headers=headers,
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(transport={self._config.type!r}, "
            f"base_url={self._config.base_url!r}, initialized={self._session_id is not None})"
        )

    @property
    def next_request_id(self) -> int:
        return self._next_id

    @property
    def session_id(self) -> str | None:
        return self._session_id

    @property
    def protocol_version(self) -> str | None:
        return self._protocol_version

    async def __aenter__(self) -> "McpStreamableSession":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _validate_destination(self) -> None:
        if self._config.type == "http":
            await validate_tcp_origin(self._config, resolver=self._resolver)

    async def _send(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        headers: Mapping[str, str] | None = None,
        allow_empty: bool = False,
        ambiguous_tool_call: bool = False,
    ) -> tuple[httpx.Response, list[Any]]:
        await self._validate_destination()
        request_headers = dict(headers or {})
        try:
            async with self._client.stream(
                method,
                path,
                json=json_body,
                headers=request_headers,
            ) as response:
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > MCP_RESPONSE_MAX_BYTES:
                        raise SamSchemaError("SAM response exceeds the 4 MiB limit")
                    chunks.append(chunk)
                body = b"".join(chunks)
        except SamError:
            raise
        except (httpx.TimeoutException, httpx.TransportError, EOFError, OSError) as exc:
            if ambiguous_tool_call:
                raise SamCallAmbiguous(
                    "SAM tools/call outcome is ambiguous after transport failure",
                    phase="dispatch_or_response",
                    dispatched=None,
                ) from exc
            raise SamConnectivityError(
                "SAM transport failed",
                phase="transport",
                dispatched=None,
            ) from exc

        if 300 <= response.status_code < 400:
            raise SamSchemaError("SAM redirect was rejected")
        if response.status_code == 401:
            raise SamAuthRequired("SAM authentication is required")
        if response.status_code == 403:
            raise SamAuthRejected("SAM authentication was rejected")
        if response.status_code == 503:
            raise SamNodeNotReady("SAM node is not ready")
        if response.status_code < 200 or response.status_code >= 300:
            raise SamProviderError(
                f"SAM returned HTTP status {response.status_code}",
                status_code=response.status_code,
            )
        if not body:
            if allow_empty:
                return response, []
            raise SamSchemaError("SAM returned an empty response")

        media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media_type == "application/json":
            values = [_decode_json_bytes(body)]
        elif media_type == "text/event-stream":
            values = _decode_sse_bytes(body)
        else:
            raise SamSchemaError("SAM returned an unsupported media type")
        return response, values

    async def get_json(self, path: str) -> Any:
        _, values = await self._send("GET", path)
        if len(values) != 1:
            raise SamSchemaError("SAM JSON endpoint returned multiple payloads")
        return values[0]

    @staticmethod
    def _validate_initialize_result(result: Mapping[str, Any]) -> str:
        protocol = result.get("protocolVersion")
        capabilities = result.get("capabilities")
        server_info = result.get("serverInfo")
        instructions = result.get("instructions", "")
        if protocol not in MCP_PROTOCOL_VERSIONS:
            raise SamSchemaError("MCP initialize negotiated an unsupported protocol version")
        if not isinstance(capabilities, Mapping):
            raise SamSchemaError("MCP initialize capabilities must be an object")
        if not isinstance(server_info, Mapping):
            raise SamSchemaError("MCP initialize serverInfo must be an object")
        for field in ("name", "version"):
            value = server_info.get(field)
            if not isinstance(value, str) or not value:
                raise SamSchemaError(
                    f"MCP initialize serverInfo.{field} must be a nonempty string"
                )
        if not isinstance(instructions, str):
            raise SamSchemaError("MCP initialize instructions must be a string")
        return protocol

    async def initialize(self) -> dict[str, Any]:
        if self._session_id is not None:
            raise SamSchemaError("MCP session is already initialized")
        result, response = await self._request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "a0-sam-mesh", "version": "1.0.0"},
            },
            include_session=False,
        )
        session_id = response.headers.get("mcp-session-id")
        protocol = self._validate_initialize_result(result)
        response_protocol = response.headers.get("mcp-protocol-version")
        if not session_id:
            raise SamSchemaError("MCP initialize omitted Mcp-Session-Id")
        if response_protocol is not None and response_protocol != protocol:
            raise SamSchemaError("MCP initialize returned conflicting protocol versions")

        staged_headers = {
            "Mcp-Session-Id": session_id,
            "Mcp-Protocol-Version": protocol,
        }
        payload = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }
        await self._send(
            "POST",
            "/mcp",
            json_body=payload,
            headers=staged_headers,
            allow_empty=True,
        )
        self._session_id, self._protocol_version = session_id, protocol
        return result

    async def notification(self, method: str, params: dict[str, Any]) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        await self._send(
            "POST",
            "/mcp",
            json_body=payload,
            headers=self._session_headers(),
            allow_empty=True,
        )

    def _session_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self._session_id is not None:
            headers["Mcp-Session-Id"] = self._session_id
        if self._protocol_version is not None:
            headers["Mcp-Protocol-Version"] = self._protocol_version
        return headers

    @staticmethod
    def _matching_message(values: list[Any], request_id: int) -> Mapping[str, Any]:
        matching: list[Mapping[str, Any]] = []
        for value in values:
            if not isinstance(value, Mapping):
                continue
            response_id = value.get("id")
            if response_id == request_id and type(response_id) is not type(request_id):
                raise SamSchemaError("MCP response id used an invalid type alias")
            if type(response_id) is type(request_id) and response_id == request_id:
                matching.append(value)
        if len(matching) != 1:
            raise SamSchemaError(
                "MCP response did not contain exactly one matching request id"
            )
        return matching[0]

    @staticmethod
    def _validate_error(error: Any) -> Mapping[str, Any]:
        if not isinstance(error, Mapping):
            raise SamSchemaError("MCP error must be an object")
        code = error.get("code")
        message = error.get("message")
        valid_code = isinstance(code, int) and not isinstance(code, bool)
        if not valid_code or not isinstance(message, str) or not message:
            raise SamSchemaError("MCP error must contain a valid code and message")
        return error

    async def _request(
        self,
        method: str,
        params: dict[str, Any],
        *,
        include_session: bool = True,
    ) -> tuple[dict[str, Any], httpx.Response]:
        request_id = self._next_id
        self._next_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        tool_call = method == "tools/call"
        try:
            response, values = await self._send(
                "POST",
                "/mcp",
                json_body=payload,
                headers=self._session_headers() if include_session else {},
                ambiguous_tool_call=tool_call,
            )
            message = self._matching_message(values, request_id)
            if message.get("jsonrpc") != "2.0":
                raise SamSchemaError("MCP response has an invalid JSON-RPC version")
            has_result = "result" in message
            has_error = "error" in message
            if has_result == has_error:
                raise SamSchemaError(
                    "MCP response must contain exactly one result or error"
                )
            if has_error:
                error = self._validate_error(message["error"])
                if _machine_policy_denial({"error": error}):
                    raise SamPolicyDenied("SAM policy denied the MCP request")
                raise SamProviderError(
                    f"SAM MCP request failed with code {error['code']!r}"
                )
            result = message["result"]
            if not isinstance(result, Mapping):
                raise SamSchemaError("MCP response result must be an object")
        except SamSchemaError as exc:
            if tool_call:
                raise SamCallAmbiguous(
                    "SAM tools/call returned an unusable response",
                    phase="response",
                    dispatched=True,
                ) from exc
            raise
        return dict(result), response

    async def request(
        self,
        method: str,
        params: dict[str, Any],
        *,
        include_session: bool = True,
    ) -> dict[str, Any]:
        result, _ = await self._request(
            method,
            params,
            include_session=include_session,
        )
        return result

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(arguments, dict):
            raise SamSchemaError("MCP tool arguments must be an object")
        return await self.request("tools/call", {"name": name, "arguments": arguments})
