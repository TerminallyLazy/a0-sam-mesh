"""Destination-aware preflight and one-shot invocation; no model approval API."""
import asyncio
import json
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from jsonschema import Draft202012Validator

from .audit import AuditEvent
from .decisions import DecisionError
from .domain import DataClass, PreflightDecision, RiskLevel, RouteMode, Scope
from .leases import LeaseRequest, argument_binding_hash, risk_assessment_binding_hash
from .mcp_transport import SamCallAmbiguous, SamError
from .passport import evaluate
from .sam_client import _plain_json
from .risk import classify
from .storage import canonical_hash, copy_plain_json, timestamp_text


@dataclass(frozen=True)
class ToolResult:
    error_code: str | None = None
    content: tuple = field(default=(), repr=False)
    untrusted: bool = True


def route_hash(config):
    transport = config.transport
    return canonical_hash({
        'transport': transport.type, 'url': transport.base_url,
        'socket': transport.socket_path, 'origins': list(transport.allowed_origins),
        # Only a digest of the credential contributes to an encrypted decision binding.
        'credential': canonical_hash(transport.token, domain='gate-credential'),
        'features': config.features.remote_calls,
    }, domain='gate-route')


def binding(config, tool, arguments, data_class, assessment):
    return LeaseRequest(
        config.scope, tool.peer_id, tool.service, tool.canonical_uri, tool.schema_hash,
        tool.risk_metadata_hash(), config.passport.version_hash(), RouteMode.PINNED, None,
        config.passport.inference.required_labels, 'arguments', argument_binding_hash(arguments),
        data_class, assessment.level, risk_assessment_binding_hash(assessment))


class DelegationGate:
    def __init__(self, resolve, adapter, decisions, leases, audit):
        self.resolve = resolve
        self.adapter = adapter
        self.decisions = decisions
        self.leases = leases
        self.audit = audit
        self.scope = resolve().scope

    def _policy(self, config, tool, arguments, data_class):
        schema = _plain_json(tool.input_schema)
        # Reject external references: validating arguments must never fetch a URL.
        def local_only(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in {'$ref', '$dynamicRef'}:
                        raise DecisionError('unsupported_schema_reference')
                    local_only(item)
            elif isinstance(value, list):
                for item in value:
                    local_only(item)
        local_only(schema)
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(arguments)
        assessment = classify(tool, arguments)
        decision = evaluate(config.passport, tool, data_class, risk_assessment=assessment,
                            remote_calls_enabled=config.features.remote_calls)
        return assessment, decision

    def _boundary_error(self, config):
        # No TCP transmission, including discovery credentials, until connected-peer pinning.
        if config.transport.type != 'uds':
            return 'unverified_route'
        if not self.adapter.risk_metadata_verified:
            return 'risk_metadata_unavailable'
        if self.decisions.disabled(config.scope):
            return 'emergency_disconnected'
        return None

    async def preflight(self, peer_id, tool_name, arguments, data_class):
        if not isinstance(data_class, DataClass) or type(arguments) is not dict:
            raise DecisionError('invalid_arguments')
        arguments = copy_plain_json(arguments)
        if len(json.dumps(arguments).encode()) > 16384:
            raise DecisionError('arguments_too_large')
        config = self.resolve()
        # Describe accepts identity only, never the sensitive payload.
        tool = await self.adapter.describe(peer_id, tool_name)
        if tool.peer_id != peer_id or tool.canonical_uri != tool_name:
            raise DecisionError('destination_changed')
        assessment, policy = self._policy(config, tool, arguments, data_class)
        error = self._boundary_error(config)
        outcome = 'deny' if error else policy.outcome
        request = binding(config, tool, arguments, data_class, assessment)
        payload = dict(peer_id=peer_id, tool_name=tool_name, arguments=arguments,
                       data_class=data_class.value, binding=request.binding_hash(),
                       route=route_hash(config), labels=list(tool.labels), lease_id=None,
                       outcome=outcome, request=asdict(request))
        payload = json.loads(json.dumps(payload))
        identifier = self.decisions.create(config.scope, payload)
        return PreflightDecision(
            identifier, config.scope, config.passport.version_hash(), peer_id, tool.service,
            tool, (), data_class, assessment.level, assessment.evidence, RouteMode.PINNED,
            policy.required_labels, assessment.requires_single_use_lease, outcome,
            (error,) if error else policy.reasons,
            timestamp_text(self.decisions.storage.now() + timedelta(seconds=300)))

    def approve(self, decision_id, *, approver_id):
        """Trusted future authenticated API only. Never exported as a model tool."""
        config = self.resolve()
        payload = self.decisions.load(config.scope, decision_id)
        if self._boundary_error(config) or payload['outcome'] != 'needs_approval':
            raise DecisionError('policy_denied')
        # Approval uses the server's original exact request, never caller-supplied authority.
        values = dict(payload['request'])
        values['scope'] = Scope(**values['scope'])
        values['route_mode'] = RouteMode(values['route_mode'])
        values['data_class'] = DataClass(values['data_class'])
        values['risk_level'] = RiskLevel(values['risk_level'])
        values['required_labels'] = tuple(values['required_labels'])
        request = LeaseRequest(**values)
        if (request.binding_hash() != payload['binding']
                or request.scope != config.scope
                or request.passport_hash != config.passport.version_hash()
                or payload['route'] != route_hash(config)):
            raise DecisionError('new_preflight_required')
        lease = self.leases.issue(request, 300, 1, approver_id=approver_id)
        payload['lease_id'] = lease.id
        self.decisions.update(config.scope, decision_id, payload)

    def emergency_disconnect(self):
        scope = self.scope
        self.decisions.revoke_scope(scope)
        self.leases.revoke_scope(scope)

    def _audit(self, config, identifier, assessment, data_class, outcome, error=None):
        self.audit.append(AuditEvent(
            config.scope, 'remote_call', None, identifier, None, assessment.level,
            data_class, RouteMode.PINNED, outcome, None, 0, error, {}))

    async def invoke(self, decision_id):
        config = self.resolve()
        claimed = False
        dispatched = False
        try:
            error = self._boundary_error(config)
            if error:
                return ToolResult(error)
            payload = self.decisions.load(config.scope, decision_id)
            tool = await self.adapter.describe(payload['peer_id'], payload['tool_name'])
            # Re-resolve after the last awaited network operation, immediately before dispatch.
            config = self.resolve()
            data_class = DataClass(payload['data_class'])
            arguments = payload['arguments']
            assessment, policy = self._policy(config, tool, arguments, data_class)
            request = binding(config, tool, arguments, data_class, assessment)
            if (request.binding_hash() != payload['binding']
                    or route_hash(config) != payload['route']
                    or list(tool.labels) != payload['labels']):
                self.decisions.invalidate(config.scope, decision_id)
                return ToolResult('schema_or_boundary_changed')
            error = self._boundary_error(config)
            if error or policy.outcome == 'deny' or payload['outcome'] == 'deny':
                return ToolResult(error or 'policy_denied')
            if policy.outcome == 'needs_approval' and not payload['lease_id']:
                return ToolResult('approval_required')
            self.decisions.claim(config.scope, decision_id,
                                 config.passport.limits.calls_per_session, payload)
            claimed = True
            if policy.outcome == 'needs_approval' or assessment.requires_single_use_lease:
                consumed = self.leases.consume(payload['lease_id'], request)
                if not consumed.allowed:
                    return ToolResult(consumed.reason)
            try:
                self._audit(config, decision_id, assessment, data_class, 'dispatch')
            except Exception:
                return ToolResult('audit_storage_unavailable')
            if self.decisions.disabled(config.scope):
                return ToolResult('emergency_disconnected')
            dispatched = True
            async with asyncio.timeout(config.passport.limits.timeout_seconds):
                result = await self.adapter.call(tool, arguments, policy.required_labels_wire)
            # Raw remote content is deliberately not inserted in model history here.
            # Read-only public output uses the bounded inspector owned by native_tools.
            from .tool_output import inspect_result
            content = inspect_result(result, arguments, config.transport.token, data_class)
            self._audit(config, decision_id, assessment, data_class, 'success')
            return ToolResult(content=content)
        except DecisionError as exc:
            return ToolResult(str(exc))
        except SamCallAmbiguous:
            return ToolResult('duplicate_execution_possible')
        except asyncio.CancelledError:
            raise
        except (SamError, TimeoutError):
            return ToolResult('duplicate_execution_possible' if dispatched
                              else 'destination_unavailable')
        except Exception:
            return ToolResult('duplicate_execution_possible' if dispatched else 'gate_unavailable')
        finally:
            if claimed:
                self.decisions.finish(config.scope, decision_id)
