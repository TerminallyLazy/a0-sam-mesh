"""Named recipient approval for protected inference payloads, without nested agents."""

import asyncio
import json
import re
import time
from dataclasses import asdict
from urllib.parse import urlsplit

from .audit import AuditEvent
from .decisions import DecisionError
from .domain import DataClass, RiskLevel, RouteMode
from .gate import route_hash
from .inference import _model, inference_error
from .leases import LeaseRequest, argument_binding_hash
from .mcp_transport import SamAuthRejected, SamAuthRequired, SamProviderError
from .remote_tools import RemoteTools
from .storage import canonical_hash
from .tool_output import safe_output


async def discover_route(client, peer_id, service):
    if (
        type(peer_id) is not str
        or not re.fullmatch(r"[A-Za-z0-9]{3,128}", peer_id)
        or type(service) is not str
        or not re.fullmatch(r"[a-z][a-z0-9-]{2,62}", service)
    ):
        raise DecisionError("invalid_inference_destination")
    catalog = await RemoteTools(client).read(
        "discover_remote_services",
        {"type": "inference", "name": service, "limit": 100, "offset": 0},
    )
    if type(catalog) is not list:
        raise DecisionError("inference_catalog_unavailable")
    matches = [
        r
        for r in catalog
        if type(r) is dict and r.get("peer_id") == peer_id and r.get("srv_name") == service
    ]
    if len(matches) != 1:
        raise DecisionError("inference_destination_unavailable")
    root = matches[0].get("local_proxy_url")
    if type(root) is not str:
        raise DecisionError("invalid_discovered_proxy")
    parsed, node = urlsplit(root), urlsplit(client.mcp._config.base_url)
    expected = f"/sam/{peer_id}/inference/{service}"
    if (
        (parsed.scheme, parsed.netloc) != (node.scheme, node.netloc)
        or parsed.path.rstrip("/") != expected
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise DecisionError("invalid_discovered_proxy")
    # Current SAM publishes a proxy root whose backend already owns the API prefix.
    return {
        "peer_id": peer_id,
        "service": service,
        "proxy_root": root.rstrip("/"),
        "path": expected + "/chat/completions",
    }


class InferenceGate:
    def __init__(self, resolve, client, stores):
        self.resolve, self.client = resolve, client
        self.decisions, self.leases, self.audit = stores

    def _audit(self, config, identifier, payload, outcome, *, started=None, error=None):
        latency = 0 if started is None else min(86400000, int((time.monotonic() - started) * 1000))
        self.audit.append(
            AuditEvent(
                config.scope,
                "inference",
                payload["tool_name"],
                identifier,
                payload.get("lease_id"),
                RiskLevel.NETWORK,
                DataClass(payload["data_class"]),
                RouteMode.PINNED,
                outcome,
                latency,
                0,
                error,
                {"single_use": True},
            )
        )

    def _config(self, data_class):
        config = self.resolve()
        if self.decisions.disabled(config.scope):
            raise DecisionError("emergency_disconnected")
        if not config.features.mesh_inference or not config.passport.inference.enabled:
            raise DecisionError("mesh_inference_disabled")
        if data_class != DataClass.PUBLIC and config.passport.inference.sensitive_data == "deny":
            raise DecisionError("sensitive_inference_denied")
        order = list(DataClass)
        if order.index(data_class) > order.index(config.passport.outbound.max_data_class):
            raise DecisionError("data_class_denied")
        return config

    def _binding(self, config, route, model, payload, data_class):
        fingerprint = canonical_hash(route, domain="inference-route")
        return LeaseRequest(
            config.scope,
            route["peer_id"],
            route["service"],
            f"inference://{route['service']}/chat/completions",
            fingerprint,
            fingerprint,
            config.passport.version_hash(),
            RouteMode.PINNED,
            model,
            config.passport.inference.required_labels,
            "arguments",
            argument_binding_hash(payload),
            data_class,
            RiskLevel.NETWORK,
            canonical_hash("inference", domain="inference-risk"),
        )

    async def preflight(self, peer_id, service, model, message, data_class):
        _model(model)
        data_class = DataClass(data_class)
        config = self._config(data_class)
        if type(message) is not str or not 1 <= len(message.encode()) <= 16384:
            raise DecisionError("invalid_inference_payload")
        if config.transport.token and config.transport.token in message:
            raise DecisionError("credential_payload_denied")
        route = await discover_route(self.client, peer_id, service)
        body = {
            "model": model,
            "messages": [{"role": "user", "content": message}],
            "max_tokens": 1024,
            "stream": False,
        }
        request = self._binding(config, route, model, body, data_class)
        payload = {
            "kind": "inference",
            "peer_id": peer_id,
            "tool_name": request.canonical_uri,
            "arguments": body,
            "data_class": data_class.value,
            "request": asdict(request),
            "binding": request.binding_hash(),
            "route": route_hash(config),
            "inference_route": route,
            "outcome": "needs_approval",
            "lease_id": None,
            "protected_payload": True,
        }
        identifier = self.decisions.create(config.scope, json.loads(json.dumps(payload)))
        self._audit(config, identifier, payload, "needs_approval")
        return identifier

    def approve(self, identifier, acknowledgment):
        if acknowledgment != "APPROVE":
            raise DecisionError("acknowledgment_required")
        config = self.resolve()
        payload = self.decisions.load(config.scope, identifier)
        if payload.get("kind") != "inference" or payload.get("lease_id"):
            raise DecisionError("invalid_inference_decision")
        config = self._config(DataClass(payload["data_class"]))
        request = self._binding(
            config,
            payload["inference_route"],
            payload["arguments"]["model"],
            payload["arguments"],
            DataClass(payload["data_class"]),
        )
        if request.binding_hash() != payload["binding"] or route_hash(config) != payload["route"]:
            raise DecisionError("new_preflight_required")
        payload["lease_id"] = self.leases.issue(
            request,
            min(300, config.passport.limits.approval_lease_minutes * 60),
            1,
            approver_id="authenticated-local-operator",
        ).id
        self.decisions.update(config.scope, identifier, payload)
        self._audit(config, identifier, payload, "approved")
        return {"approved": True, "single_use": True, "decision_id": identifier}

    async def invoke(self, identifier):
        config = self.resolve()
        original_scope = config.scope
        payload = self.decisions.load(config.scope, identifier)
        if payload.get("kind") != "inference" or not payload.get("lease_id"):
            raise DecisionError("approval_required")
        config = self._config(DataClass(payload["data_class"]))
        try:
            route = await discover_route(
                self.client, payload["peer_id"], payload["inference_route"]["service"]
            )
        except BaseException:
            self.decisions.invalidate(original_scope, identifier)
            raise
        config = self._config(DataClass(payload["data_class"]))
        request = self._binding(
            config,
            route,
            payload["arguments"]["model"],
            payload["arguments"],
            DataClass(payload["data_class"]),
        )
        if (
            config.scope != original_scope
            or request.binding_hash() != payload["binding"]
            or route_hash(config) != payload["route"]
        ):
            self.decisions.invalidate(original_scope, identifier)
            raise DecisionError("inference_destination_changed")
        self.decisions.claim(
            config.scope, identifier, config.passport.limits.calls_per_session, payload
        )
        started = time.monotonic()
        outcome, error = "failure", "inference_transport_failure"
        degraded = []
        try:
            result = self.leases.consume(payload["lease_id"], request)
            if not result.allowed:
                raise DecisionError(result.reason)
            # Durable evidence is required before a sensitive payload can leave.
            self._audit(config, identifier, payload, "admitting")
            self.decisions.admit(config.scope, identifier, payload)
            # The client has X-Sam-Authentication only. Never send the node token in
            # Authorization on a named proxy: that header belongs to the remote provider.
            async with asyncio.timeout(config.passport.limits.timeout_seconds):
                _, values = await self.client.mcp._send(
                    "POST",
                    route["path"],
                    json_body=payload["arguments"],
                    headers={
                        "X-Sam-Required-Labels": ",".join(config.passport.inference.required_labels)
                    },
                )
            if (
                len(values) != 1
                or type(values[0]) is not dict
                or not isinstance(values[0].get("choices"), list)
                or not values[0]["choices"]
            ):
                raise DecisionError("malformed_inference_response")
            outcome, error = "success", None
            output = safe_output(
                {"status": "verified_now", "untrusted": True, "response": values[0]},
                token=config.transport.token,
            )
        except asyncio.CancelledError:
            outcome, error = "cancellation", "inference_cancelled"
            raise
        except DecisionError as exc:
            error = str(exc)
            raise
        except (SamAuthRequired, SamAuthRejected) as exc:
            error = "auth_required" if isinstance(exc, SamAuthRequired) else "auth_rejected"
            raise DecisionError(error) from None
        except SamProviderError as exc:
            error = inference_error(exc.status_code)
            raise DecisionError(error) from None
        except Exception:
            raise DecisionError(error) from None
        finally:
            try:
                self._audit(config, identifier, payload, outcome, started=started, error=error)
            except Exception:
                degraded.append("audit_failed")
            try:
                self.decisions.finish(original_scope, identifier)
            except Exception:
                degraded.append("cleanup_failed")
        if degraded:
            output["degraded"] = degraded
        return output
