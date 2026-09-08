"""Installed Agent Zero coordinator. Reuse stores, close network sessions per tool."""
import asyncio
import json
import threading
from collections import OrderedDict
from dataclasses import asdict

from .audit import AuditStore
from .config import resolve_config
from .decisions import DecisionStore
from .domain import DataClass
from .gate import DelegationGate
from .leases import LeaseStore
from .native_tools import validate_arguments
from .mcp_transport import (
    SamAuthRequired, SamAuthRejected, SamSchemaError, SamPolicyDenied,
    SamNodeNotReady, SamCallAmbiguous, SamConnectivityError, SamProviderError,
)
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
        type='tool', heading='SAM Mesh tool', content='', kvps={}, _tool_name=tool.name)


async def execute_native(tool, name, arguments):
    try:
        if tool.method:
            raise ValueError('invalid_tool_arguments')
        arguments = validate_arguments(name, arguments)
    except Exception:
        return json.dumps({'error_code': 'invalid_tool_arguments'})
    try:
        value = await dispatch(tool.agent, name, arguments)
        return json.dumps(value, allow_nan=False)
    except asyncio.CancelledError:
        raise
    except (SamAuthRequired, SamAuthRejected, SamSchemaError, SamPolicyDenied,
            SamNodeNotReady, SamCallAmbiguous, SamConnectivityError, SamProviderError) as exc:
        codes = {SamAuthRequired: 'auth_required', SamAuthRejected: 'auth_rejected',
                 SamSchemaError: 'schema_changed', SamPolicyDenied: 'policy_denied',
                 SamNodeNotReady: 'node_not_ready',
                 SamCallAmbiguous: 'duplicate_execution_possible',
                 SamConnectivityError: 'destination_unavailable',
                 SamProviderError: 'provider_exhausted'}
        return json.dumps({'error_code': codes.get(type(exc), 'destination_unavailable')})
    except Exception:
        # Never echo configuration, exceptions, tool arguments or resolved credentials.
        return json.dumps({'error_code': 'sam_unavailable', 'status': 'unreachable'})


async def dispatch(agent, name, arguments):
    config = resolve_config(agent)
    if config.transport.type != 'uds':
        return {'error_code': 'unverified_route', 'status': 'unsupported'}
    timeout = config.passport.limits.discovery_timeout_seconds
    async with SamClient(config.transport, timeout_seconds=timeout) as client:
        adapter = RemoteTools(client)
        if name == 'sam_mesh_status':
            health = await client.health()
            return {'status': 'verified_now', 'ready': health.ready,
                    'guarded_invocation': 'unsupported',
                    'reason': 'risk_metadata_unavailable'}
        if name == 'sam_list_models':
            models = await client.list_models()
            return safe_output({'status': 'verified_now', 'untrusted': True,
                                'models': [asdict(model) for model in models]})
        reads = {'sam_list_local_services': 'list_local_services',
                 'sam_discover_services': 'discover_remote_services',
                 'sam_find_tools': 'find_remote_tools'}
        if name in reads:
            result = await adapter.read(reads[name], arguments)
            return safe_output({'status': 'partial', 'untrusted': True, 'data': result})
        if name in {'sam_describe_tool', 'sam_route_preview'}:
            descriptor = await adapter.describe(**arguments)
            return safe_output({'status': 'partial', 'untrusted': True,
                'canonical_uri': descriptor.canonical_uri, 'peer_id': descriptor.peer_id,
                'service': descriptor.service, 'schema_hash': descriptor.schema_hash,
                'risk_metadata': 'unsupported', 'route_mode': 'pinned',
                'required_labels': list(config.passport.inference.required_labels),
                'label_semantics': 'any_of', 'invocation_enabled': False})
        gate = DelegationGate(lambda: resolve_config(agent), adapter, *scoped_stores(config.scope))
        if name == 'sam_call_remote_tool':
            return asdict(await gate.invoke(arguments['decision_id']))
        if name == 'sam_preflight_tool':
            decision = await gate.preflight(arguments['peer_id'], arguments['tool_name'],
                                           arguments['arguments'],
                                           DataClass(arguments['data_class']))
            return {'decision_id': decision.decision_id, 'outcome': decision.outcome,
                    'reasons': decision.reasons, 'expires_at': decision.expires_at,
                    'risk_level': decision.risk_level.value, 'untrusted': True,
                    'duplicate_execution_possible': decision.duplicate_execution_possible}
        return {'error_code': 'unsupported_capability'}
