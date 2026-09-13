"""Protected Agent Zero API dispatcher. Scope comes from an existing host context."""

import asyncio
import json
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum

from .config import _resolve_scope, resolve_config
from .control import approve_decision, resume_scope, review_decision, stop_scope
from .decisions import DecisionError
from .domain import DataClass
from .gate import DelegationGate
from .remote_tools import RemoteTools
from .sam_client import SamClient
from .tool_output import safe_output
from .tool_runtime import dispatch, scoped_stores


def plain(value):
    if is_dataclass(value):
        return {f.name: plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Mapping):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [plain(v) for v in value]
    if isinstance(value, Enum):
        return value.value
    return value


_INPUTS = {
    "status": set(),
    "catalog": {"kind", "query"},
    "audit": {"export"},
    "preflight": {"peer_id", "tool_name", "arguments", "data_class"},
    "approve": {"decision_id", "acknowledgment"},
    "revoke": {"decision_id"},
    "review": {"decision_id"},
    "emergency_disconnect": set(),
    "resume": {"acknowledgment"},
    "native_mcp_plan": set(),
    "route_preview": {"route"},
    "publication_plan": {"service"},
    "publication_start": {"service", "acknowledgment"},
    "publication_status": set(),
    "publication_close": {"name"},
    "deployment_status": set(),
    "inference_profile": {"model"},
    "inference_probe": {"model", "stream"},
    "inference_preflight": {"peer_id", "service", "model", "message", "data_class"},
    "inference_approve": {"decision_id", "acknowledgment"},
    "inference_invoke": {"decision_id"},
}


async def process(action, data, request):
    """Never let ApiHandler print raw exception paths or credential-bearing inputs."""
    try:
        if (
            type(data) is not dict
            or action not in _INPUTS
            or data.keys() - _INPUTS[action] - {"context_id"}
            or len(json.dumps(data).encode()) > 65536
        ):
            raise DecisionError("invalid_request")
        context_id = data.get("context_id")
        if type(context_id) is not str or not context_id or len(context_id) > 128:
            raise DecisionError("context_required")
        from agent import AgentContext

        context = AgentContext.get(context_id)
        if context is None:
            raise DecisionError("context_not_found")
        from helpers.plugins import get_enabled_plugins

        if (
            "sam_mesh" not in get_enabled_plugins(context.agent0)
            and action != "emergency_disconnect"
        ):
            raise DecisionError("plugin_disabled")
        return await dispatch_control(context.agent0, action, data)
    except asyncio.CancelledError:
        raise
    except DecisionError as exc:
        return {"ok": False, "error_code": str(exc)}
    except Exception:
        return {"ok": False, "error_code": "sam_control_unavailable", "status": "unreachable"}


async def dispatch_control(agent, action, data):
    scope = _resolve_scope(agent)
    stores = scoped_stores(scope)
    if action == "emergency_disconnect":
        # Deliberately before endpoint/secret resolution: offline and broken-config safe.
        result = stop_scope(scope, stores)
        from .embassy_runtime import runtime

        await runtime().submit("close_scope", (scope.project_name, scope.agent_profile))
        return result
    if action in {"publication_close", "publication_status"}:
        from .embassy_runtime import deployment_status, runtime

        owner = (scope.project_name, scope.agent_profile)
        if action == "publication_close":
            await runtime().submit("close", data["name"], owner)
            return {
                "closed": True,
                "withdrawal_pending": True,
                "operator_action": "Remove the service from the node configuration and restart the node. Cached advertisements may remain until expiry.",
            }
        return {
            "deployment": deployment_status(),
            "services": await runtime().submit("status", owner),
        }
    if action == "audit":
        return {
            "status": "verified_now",
            "events": plain(stores[2].list_redacted(scope, limit=100)),
            "integrity": plain(stores[2].verify_chain(scope)),
        }
    if action == "review":
        return review_decision(stores[0], scope, data["decision_id"])
    if action == "revoke":
        stores[0].invalidate(scope, data["decision_id"])
        return {"revoked": True}
    if action == "deployment_status":
        from .sovereign import guest_probe

        return await asyncio.to_thread(guest_probe)
    config = resolve_config(agent)
    if action == "resume":
        return resume_scope(scope, stores, data.get("acknowledgment"))
    if action == "status":
        local = {
            "scope": plain(scope),
            "mode": config.passport.mode.value,
            "features": plain(config.features),
            "stopped": stores[0].disabled(scope),
            "endpoint": config.transport.base_url,
            "transport": config.transport.type,
            "annotation_provenance": "unavailable",
        }
        try:
            async with asyncio.timeout(1.8):
                local.update(await dispatch(agent, "sam_mesh_status", {}))
        except Exception:
            local.update(status="unreachable", ready=False)
        return safe_output(local, token=config.transport.token)
    if action == "catalog":
        kind = data.get("kind", "mcp")
        if kind not in {"mcp", "inference"}:
            raise DecisionError("invalid_request")
        return await dispatch(
            agent,
            "sam_discover_services",
            {"type": kind, "name": data.get("query", ""), "limit": 50, "offset": 0},
        )
    if action == "publication_plan":
        from .publication import publication_plan

        return publication_plan(data["service"])
    if action == "publication_start":
        from .embassy_config import EmbassyService
        from .embassy_runtime import runtime
        from .embassy_sessions import cleanup_agent, create_agent_context
        from .publication import publication_plan

        if data.get("acknowledgment") != "PUBLISH":
            raise DecisionError("publication_acknowledgment_required")
        service = EmbassyService.from_dict(data["service"])
        owner = (scope.project_name, scope.agent_profile)
        if (service.project, service.agent_profile) != owner:
            raise DecisionError("service_scope_denied")

        def guard():
            from agent import AgentContext

            from helpers.plugins import get_enabled_plugins

            if AgentContext.get(agent.context.id) is not agent.context:
                return False
            fresh = resolve_config(agent)
            return (
                "sam_mesh" in get_enabled_plugins(agent)
                and fresh.features.inbound_publication
                and service.name in fresh.passport.inbound.services
                and (fresh.scope.project_name, fresh.scope.agent_profile) == owner
                and not stores[0].disabled(scope)
            )

        if not guard():
            raise DecisionError("inbound_publication_disabled")
        # Validate the actual host project/profile/plugin tool boundary before
        # any service becomes reachable, without sending a model prompt.
        validation_context = create_agent_context(service)
        await cleanup_agent(validation_context)
        await runtime().submit("start", service, owner, guard)
        return dict(
            publication_plan(data["service"]),
            state="healthy_not_published",
            status="verified_now",
            services=await runtime().submit("status", owner),
        )
    if action == "route_preview":
        from .inference import preview_route

        return preview_route(config, data["route"])
    if action == "inference_profile":
        from .inference import build_preset_fragment

        if stores[0].disabled(scope):
            raise DecisionError("emergency_disconnected")
        return build_preset_fragment(config, data["model"])
    if action == "inference_probe":
        from .inference import probe_chat

        if stores[0].disabled(scope):
            raise DecisionError("emergency_disconnected")
        if type(data.get("stream", False)) is not bool:
            raise DecisionError("invalid_request")
        return await probe_chat(config, data["model"], stream=data.get("stream", False))
    async with SamClient(
        config.transport, timeout_seconds=config.passport.limits.discovery_timeout_seconds
    ) as client:
        gate = DelegationGate(lambda: resolve_config(agent), RemoteTools(client), *stores)
        if action.startswith("inference_"):
            from .inference_gate import InferenceGate

            inference = InferenceGate(lambda: resolve_config(agent), client, stores)
            if action == "inference_preflight":
                identifier = await inference.preflight(
                    data["peer_id"],
                    data["service"],
                    data["model"],
                    data["message"],
                    data.get("data_class", "public"),
                )
                return review_decision(stores[0], scope, identifier)
            if action == "inference_approve":
                return inference.approve(data["decision_id"], data.get("acknowledgment"))
            if action == "inference_invoke":
                return await inference.invoke(data["decision_id"])
        if action == "native_mcp_plan":
            from .capabilities import CapabilityProbe
            from .native_mcp import build_native_mcp_plan

            return plain(build_native_mcp_plan(config, await CapabilityProbe(client).probe()))
        if action == "approve":
            return approve_decision(
                gate,
                data["decision_id"],
                data.get("acknowledgment"),
                "authenticated-local-operator",
            )
        if action == "preflight":
            if config.transport.token and config.transport.token in json.dumps(data):
                raise DecisionError("credential_payload_denied")
            decision = await gate.preflight(
                data["peer_id"],
                data["tool_name"],
                data["arguments"],
                DataClass(data.get("data_class", "public")),
            )
            payload = stores[0].load(scope, decision.decision_id)
            payload["protected_payload"] = True
            stores[0].update(scope, decision.decision_id, payload)
            return review_decision(stores[0], scope, decision.decision_id)
    raise DecisionError("unsupported_capability")
