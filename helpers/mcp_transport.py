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
    """SAM could not be reached or ended the response unexpectedly."""


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
        if _address_is_forbidden(address):
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
    code = str(error.get("code", "")).lower()
    category = str(error.get("type", error.get("category", ""))).lower()
    return code in {"policy_denied", "permission_denied", "authorization_denied"} or category in {
        "policy_denied",
        "permission_denied",
        "authorization_denied",
    }


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
            raise SamConnectivityError("SAM transport failed") from exc

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

    async def initialize(self) -> dict[str, Any]:
        if self._session_id is not None:
            raise SamSchemaError("MCP session is already initialized")
        result = await self.request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "a0-sam-mesh", "version": "1.0.0"},
            },
            include_session=False,
        )
        if self._session_id is None:
            raise SamSchemaError("MCP initialize omitted Mcp-Session-Id")
        await self.notification("notifications/initialized", {})
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

    async def request(
        self,
        method: str,
        params: dict[str, Any],
        *,
        include_session: bool = True,
    ) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        response, values = await self._send(
            "POST",
            "/mcp",
            json_body=payload,
            headers=self._session_headers() if include_session else {},
        )
        if method == "initialize":
            session_id = response.headers.get("mcp-session-id")
            if not session_id:
                raise SamSchemaError("MCP initialize omitted Mcp-Session-Id")
            self._session_id = session_id

        matching = [
            value
            for value in values
            if isinstance(value, Mapping) and value.get("id") == request_id
        ]
        if len(matching) != 1:
            raise SamSchemaError("MCP response did not contain exactly one matching request id")
        message = matching[0]
        if message.get("jsonrpc") != "2.0":
            raise SamSchemaError("MCP response has an invalid JSON-RPC version")
        if "error" in message:
            if _machine_policy_denial(message):
                raise SamPolicyDenied("SAM policy denied the MCP request")
            error = message.get("error")
            code = error.get("code") if isinstance(error, Mapping) else None
            raise SamProviderError(f"SAM MCP request failed with code {code!r}")
        result = message.get("result")
        if not isinstance(result, Mapping):
            raise SamSchemaError("MCP response result must be an object")
        if method == "initialize":
            protocol = result.get("protocolVersion")
            if not isinstance(protocol, str) or not protocol:
                raise SamSchemaError("MCP initialize omitted the negotiated protocol version")
            response_protocol = response.headers.get("mcp-protocol-version")
            if response_protocol is not None and response_protocol != protocol:
                raise SamSchemaError("MCP initialize returned conflicting protocol versions")
            self._protocol_version = protocol
        return dict(result)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(arguments, dict):
            raise SamSchemaError("MCP tool arguments must be an object")
        return await self.request("tools/call", {"name": name, "arguments": arguments})
