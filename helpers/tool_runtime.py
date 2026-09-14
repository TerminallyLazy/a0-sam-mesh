"""Installed Agent Zero coordinator. Reuse stores, close network sessions per tool."""

import asyncio
import json
import threading
from collections import OrderedDict
from dataclasses import asdict

from .audit import AuditStore
from .config import resolve_config
from .decisions import DecisionError, DecisionStore
from .domain import DataClass
from .gate import DelegationGate
from .leases import LeaseStore
from .mcp_transport import (
    SamAuthRejected,
    SamAuthRequired,
    SamCallAmbiguous,
    SamConnectivityError,
    SamNodeNotReady,
    SamPolicyDenied,
    SamProviderError,
    SamSchemaError,
)
from .native_tools import validate_arguments
from .remote_tools import RemoteTools
from .sam_client import SamClient
from .tool_output import safe_output

_STORES = OrderedDict()
_LOCK = threading.RLock()


def scoped_stores(scope):
    key = (scope.project_name, scope.agent_profile)
    with _LOCK:
        if key not in _STORES:
            _STORES[key] = (DecisionStore(), LeaseStore(), AuditStore())
        _STORES.move_to_end(key)
        while len(_STORES) > 4:
            _STORES.popitem(last=False)
        return _STORES[key]


async def before_native(tool):
    # Framework default logs complete tool arguments. Never call it for this surface.
    tool.log = tool.agent.context.log.log(
        type="tool", heading="SAM Mesh tool", content="", kvps={}, _tool_name=tool.name
    )


async def execute_native(tool, name, arguments):
    try:
        if tool.method:
            raise ValueError("invalid_tool_arguments")
        arguments = validate_arguments(name, arguments)
    except Exception:
        return json.dumps({"error_code": "invalid_tool_arguments"})
    try:
        value = await dispatch(tool.agent, name, arguments)
        return json.dumps(value, allow_nan=False)
    except asyncio.CancelledError:
        raise
    except DecisionError as exc:
        return json.dumps({"error_code": str(exc), "status": "unsupported"})
    except (
        SamAuthRequired,
        SamAuthRejected,
        SamSchemaError,
        SamPolicyDenied,
        SamNodeNotReady,
        SamCallAmbiguous,
        SamConnectivityError,
        SamProviderError,
    ) as exc:
        codes = {
            SamAuthRequired: "auth_required",
            SamAuthRejected: "auth_rejected",
            SamSchemaError: "schema_changed",
            SamPolicyDenied: "policy_denied",
            SamNodeNotReady: "node_not_ready",
            SamCallAmbiguous: "duplicate_execution_possible",
            SamConnectivityError: "destination_unavailable",
            SamProviderError: "provider_exhausted",
        }
        return json.dumps({"error_code": codes.get(type(exc), "destination_unavailable")})
    except Exception:
        # Never echo configuration, exceptions, tool arguments or resolved credentials.
        return json.dumps({"error_code": "sam_unavailable", "status": "unreachable"})


async def dispatch(agent, name, arguments):
    config = resolve_config(agent)
    if name == "sam_preflight_tool" and arguments.get("data_class") != "public":
        return {"error_code": "sensitive_payload_workflow_unsupported"}
    if config.transport.token and config.transport.token in json.dumps(arguments):
        return {"error_code": "credential_payload_denied"}
    value = await _dispatch(config, agent, name, arguments)
    return safe_output(value, token=config.transport.token)


async def _dispatch(config, agent, name, arguments):
    timeout = config.passport.limits.discovery_timeout_seconds
    client = SamClient(config.transport, timeout_seconds=timeout)
    value = None
    primary = None
    try:
        value = await _dispatch_client(config, agent, name, arguments, client)
        return value
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            await client.aclose()
        except Exception:
            if primary is not None:
                primary.add_note("sam_client_cleanup_failed")
            elif isinstance(value, dict):
                value.setdefault("degraded", []).append("client_cleanup_failed")


async def _dispatch_client(config, agent, name, arguments, client):
    adapter = RemoteTools(client)
    if name == "sam_mesh_status":
        health = await client.health()
        # SAM's public health routes say only that its HTTP process is alive.
        # Model catalog access requires a connected node and valid credentials.
        models = await client.list_models()
        return {
            "status": "verified_now",
            "ready": health.ready,
            "authenticated": True,
            "model_count": len(models),
            "guarded_invocation": (
                "public_single_use_approval" if config.features.remote_calls else "disabled"
            ),
            "annotation_provenance": "unavailable",
        }
    if name == "sam_list_models":
        models = await client.list_models()
        return safe_output(
            {
                "status": "verified_now",
                "untrusted": True,
                "models": [asdict(model) for model in models],
            }
        )
    reads = {
        "sam_list_local_services": "list_local_services",
        "sam_discover_services": "discover_remote_services",
        "sam_find_tools": "find_remote_tools",
    }
    if name in reads:
        result = await adapter.read(reads[name], arguments)
        return safe_output({"status": "partial", "untrusted": True, "data": result})
    if name in {"sam_describe_tool", "sam_route_preview"}:
        descriptor = await adapter.describe(**arguments)
        if name == "sam_describe_tool":
            from .schema_guard import checked_schema

            try:
                schema = checked_schema(descriptor.input_schema)
            except DecisionError:
                return {
                    "error_code": "unsupported_schema",
                    "status": "unsupported",
                    "untrusted": True,
                    "truncated": False,
                }
            return {
                "status": "partial",
                "untrusted": True,
                "canonical_uri": descriptor.canonical_uri,
                "peer_id": descriptor.peer_id,
                "input_schema": schema,
                "description": descriptor.description,
                "annotation_provenance": descriptor.annotation_provenance,
                "schema_hash": descriptor.schema_hash,
                "truncated": False,
            }
        return safe_output(
            {
                "status": "partial",
                "untrusted": True,
                "canonical_uri": descriptor.canonical_uri,
                "peer_id": descriptor.peer_id,
                "service": descriptor.service,
                "schema_hash": descriptor.schema_hash,
                "risk_metadata": "unsupported",
                "route_mode": "pinned",
                "required_labels": list(config.passport.inference.required_labels),
                "label_semantics": "any_of",
                "invocation_enabled": False,
            }
        )
    gate = DelegationGate(lambda: resolve_config(agent), adapter, *scoped_stores(config.scope))
    if name == "sam_call_remote_tool":
        payload = gate.decisions.load(config.scope, arguments["decision_id"])
        if payload["data_class"] != "public" and not payload.get("protected_payload"):
            return {"error_code": "sensitive_payload_workflow_unsupported"}
        return asdict(await gate.invoke(arguments["decision_id"]))
    if name == "sam_preflight_tool":
        decision = await gate.preflight(
            arguments["peer_id"],
            arguments["tool_name"],
            arguments["arguments"],
            DataClass(arguments["data_class"]),
        )
        return {
            "decision_id": decision.decision_id,
            "outcome": decision.outcome,
            "reasons": decision.reasons,
            "expires_at": decision.expires_at,
            "risk_level": decision.risk_level.value,
            "untrusted": True,
            "duplicate_execution_possible": decision.duplicate_execution_possible,
        }
    return {"error_code": "unsupported_capability"}
