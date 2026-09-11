"""Explicit automatic/pinned route disclosure and bounded inference probes."""

import asyncio
import json
from urllib.parse import urlsplit

from .decisions import DecisionError
from .domain import RouteMode
from .sam_client import SamClient


def _model(value):
    if type(value) is not str or not 1 <= len(value) <= 256 or any(ord(c) < 32 for c in value):
        raise DecisionError("invalid_model")
    return value


def preview_route(config, route):
    if type(route) is not dict or route.keys() - {"mode", "model", "peer_id", "service"}:
        raise DecisionError("invalid_route")
    model = _model(route.get("model"))
    mode = RouteMode(route.get("mode", "automatic"))
    enabled = config.features.mesh_inference and config.passport.inference.enabled
    result = {
        "mode": mode.value,
        "model": model,
        "enabled": enabled,
        "label_semantics": "any_of",
        "required_labels": list(config.passport.inference.required_labels),
        "exact_recipient": False,
        "may_fail_over": mode == RouteMode.AUTOMATIC,
    }
    if mode == RouteMode.PINNED:
        if not route.get("peer_id") or not route.get("service"):
            raise DecisionError("destination_required")
        result.update(
            enabled=False,
            status="unsupported",
            reason="fresh_discovered_proxy_and_destination_lease_required",
            peer_id=route["peer_id"],
            service=route["service"],
        )
    else:
        result.update(
            status="partial", disclosure="SAM may select or fail over between eligible providers"
        )
    return result


def build_preset_fragment(config, model):
    _model(model)
    if (
        config.transport.type != "http"
        or not config.features.mesh_inference
        or not config.passport.inference.enabled
    ):
        raise DecisionError("mesh_inference_disabled")
    if config.passport.inference.route_mode != RouteMode.AUTOMATIC:
        # Native OpenAI credentials at /sam/<peer>/... would be forwarded off-node.
        # Only the guarded adapter may use X-Sam-Authentication at that endpoint.
        raise DecisionError("pinned_native_credential_path_unsupported")
    base = config.transport.base_url.rstrip("/")
    if urlsplit(base).path not in {"", "/v1"}:
        raise DecisionError("invalid_native_api_base")
    headers = {}
    if config.passport.inference.required_labels:
        headers["X-Sam-Required-Labels"] = ",".join(config.passport.inference.required_labels)
    return {
        "provider": "sam_mesh",
        "name": model,
        "api_base": base if base.endswith("/v1") else base + "/v1",
        "kwargs": {
            "a0_api_mode": "chat",
            "extra_headers": headers,
            "num_retries": 0,
            "a0_retry_attempts": 0,
        },
        "disclosure": "SAM may select or fail over between eligible providers",
    }


def inference_error(status):
    return {
        401: "auth_required",
        403: "auth_rejected",
        404: "model_not_found",
        413: "context_too_large",
        429: "rate_limited",
        502: "provider_exhausted",
        503: "provider_exhausted",
        504: "provider_exhausted",
    }.get(status, "provider_error")


async def probe_chat(config, model, *, stream=False):
    """Explicit operator probe sends a fixed public prompt, never arbitrary user text."""
    _model(model)
    if not config.features.mesh_inference or not config.passport.inference.enabled:
        raise DecisionError("mesh_inference_disabled")
    body = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with probe-ok."}],
        "max_tokens": 8,
        "stream": bool(stream),
    }
    async with SamClient(config.transport, timeout_seconds=10) as client:
        chunks = 0
        tool_calls = False
        finished = False
        try:
            async with asyncio.timeout(15):
                async with client.mcp._client.stream(
                    "POST",
                    "/v1/chat/completions",
                    json=body,
                    headers={
                        "X-Sam-Required-Labels": ",".join(config.passport.inference.required_labels)
                    },
                ) as response:
                    if response.status_code != 200:
                        return {
                            "status": "unsupported",
                            "error_code": inference_error(response.status_code),
                        }
                    buffer = b""
                    size = 0
                    async for part in response.aiter_bytes():
                        size += len(part)
                        if size > 65536:
                            raise DecisionError("oversized_inference_response")
                        buffer += part
                        if not stream:
                            continue
                        while b"\n\n" in buffer.replace(b"\r\n", b"\n"):
                            buffer = buffer.replace(b"\r\n", b"\n")
                            event, buffer = buffer.split(b"\n\n", 1)
                            lines = [
                                line[5:].strip()
                                for line in event.splitlines()
                                if line.startswith(b"data:")
                            ]
                            if not lines:
                                continue
                            raw = b"\n".join(lines)
                            if raw == b"[DONE]":
                                finished = True
                                continue
                            if finished:
                                raise DecisionError("malformed_inference_stream")
                            value = json.loads(raw)
                            choices = value.get("choices")
                            if not isinstance(choices, list):
                                raise DecisionError("malformed_inference_stream")
                            for choice in choices:
                                delta = choice.get("delta", {})
                                if not isinstance(delta, dict):
                                    raise DecisionError("malformed_inference_stream")
                                tool_calls |= bool(delta.get("tool_calls"))
                            chunks += 1
                    if stream and (not finished or buffer.strip() or not chunks):
                        raise DecisionError("inference_stream_incomplete")
                    if not stream:
                        value = json.loads(buffer)
                        choices = value.get("choices")
                        if (
                            not isinstance(choices, list)
                            or not choices
                            or not isinstance(choices[0].get("message"), dict)
                        ):
                            raise DecisionError("malformed_inference_response")
                        tool_calls = bool(choices[0]["message"].get("tool_calls"))
                        chunks = 1
            return {
                "status": "verified_now",
                "streamed": stream,
                "chunks": chunks,
                "tool_calls_observed": tool_calls,
                "extra_retries": 0,
                "scope": "fixed_public_probe_only",
            }
        except asyncio.CancelledError:
            raise
        except DecisionError as exc:
            return {"status": "unsupported", "error_code": str(exc)}
        except Exception:
            return {"status": "unreachable", "error_code": "inference_transport_failure"}


def guard_native_model(agent, model):
    """Called immediately before chat/utility transmission in the host model loop."""
    original = getattr(model, "a0_model_conf", None)
    if getattr(original, "provider", "") != "sam_mesh":
        return model
    from .config import resolve_config
    from .tool_runtime import scoped_stores

    config = resolve_config(agent)
    if scoped_stores(config.scope)[0].disabled(config.scope):
        raise DecisionError("emergency_disconnected")
    preset = build_preset_fragment(config, getattr(original, "name", ""))
    actual = model.kwargs.get("api_base", "")
    if actual.rstrip("/") != preset["api_base"]:
        raise DecisionError("native_inference_destination_changed")
    model.kwargs["extra_headers"] = preset["kwargs"]["extra_headers"]
    model.kwargs["num_retries"] = 0
    model.kwargs["a0_retry_attempts"] = 0
    return GovernedNativeModel(agent, model)


class GovernedNativeModel:
    """Keep A0's native model/tool loop while owning the HTTP client's lifetime."""

    def __init__(self, agent, model):
        self.agent, self.model = agent, model

    def __getattr__(self, name):
        return getattr(self.model, name)

    async def unified_call(self, *args, **kwargs):
        return await self._call("unified_call", args, kwargs)

    async def unified_turn(self, *args, **kwargs):
        return await self._call("unified_turn", args, kwargs)

    async def _call(self, method, args, kwargs):
        import httpx
        from openai import AsyncOpenAI

        from .config import resolve_config
        from .tcp_transport import PinnedTcpTransport
        from .tool_runtime import scoped_stores

        config = resolve_config(self.agent)
        preset = build_preset_fragment(config, self.model.a0_model_conf.name)
        if scoped_stores(config.scope)[0].disabled(config.scope):
            raise DecisionError("emergency_disconnected")
        if self.model.kwargs.get("api_base", "").rstrip("/") != preset["api_base"]:
            raise DecisionError("native_inference_destination_changed")
        async with httpx.AsyncClient(
            transport=PinnedTcpTransport(config.transport),
            follow_redirects=False,
            trust_env=False,
            timeout=config.passport.limits.timeout_seconds,
        ) as http:
            async with AsyncOpenAI(
                base_url=preset["api_base"],
                api_key=config.transport.token or "NA",
                http_client=http,
                max_retries=0,
            ) as sdk:
                call_kwargs = dict(self.model.kwargs)
                call_kwargs.update(
                    client=sdk,
                    num_retries=0,
                    a0_retry_attempts=0,
                    extra_headers=preset["kwargs"]["extra_headers"],
                )
                model = self.model.model_copy(update={"kwargs": call_kwargs})
                stores = scoped_stores(config.scope)
                admission = stores[0].begin_native(
                    config.scope, config.passport.limits.calls_per_session
                )
                try:
                    from .audit import AuditEvent
                    from .domain import RiskLevel

                    stores[2].append(
                        AuditEvent(
                            config.scope,
                            "native_inference",
                            preset["api_base"],
                            admission,
                            None,
                            RiskLevel.NETWORK,
                            config.passport.outbound.max_data_class,
                            RouteMode.AUTOMATIC,
                            "admitted",
                            0,
                            0,
                            None,
                            {"data_class_is_passport_ceiling": True, "exact_recipient": False},
                        )
                    )
                    async with asyncio.timeout(config.passport.limits.timeout_seconds):
                        kwargs.update(
                            client=sdk,
                            num_retries=0,
                            a0_retry_attempts=0,
                            extra_headers=preset["kwargs"]["extra_headers"],
                        )
                        return await getattr(model, method)(*args, **kwargs)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    status = getattr(exc, "status_code", None)
                    raise DecisionError(
                        inference_error(status) if status else "inference_transport_failure"
                    ) from None
                finally:
                    stores[0].finish(config.scope, admission)
