"""Destination-aware preflight and one-shot invocation; no model approval API."""

import asyncio
import json
import time
from dataclasses import asdict, dataclass, field
from datetime import timedelta

from .audit import AuditEvent
from .decisions import DecisionError
from .domain import DataClass, PreflightDecision, RiskLevel, RouteMode, Scope
from .leases import LeaseRequest, argument_binding_hash, risk_assessment_binding_hash
from .mcp_transport import (
    SamAuthRejected,
    SamAuthRequired,
    SamCallAmbiguous,
    SamError,
    SamPolicyDenied,
    SamSchemaError,
)
from .passport import evaluate
from .risk import RiskAssessment, classify
from .schema_guard import validate_payload
from .storage import canonical_hash, copy_plain_json, timestamp_text


@dataclass(frozen=True)
class ToolResult:
    error_code: str | None = None
    content: tuple = field(default=(), repr=False)
    untrusted: bool = True
    execution_uncertain: bool = False
    admitted: bool = False
    degraded: list[str] = field(default_factory=list)


def route_hash(config):
    transport = config.transport
    return canonical_hash(
        {
            "transport": transport.type,
            "url": transport.base_url,
            "socket": transport.socket_path,
            "origins": list(transport.allowed_origins),
            # Only a digest of the credential contributes to an encrypted decision binding.
            "credential": canonical_hash(transport.token, domain="gate-credential"),
            "features": config.features.remote_calls,
        },
        domain="gate-route",
    )


def binding(config, tool, arguments, data_class, assessment):
    return LeaseRequest(
        config.scope,
        tool.peer_id,
        tool.service,
        tool.canonical_uri,
        tool.schema_hash,
        tool.risk_metadata_hash(),
        config.passport.version_hash(),
        RouteMode.PINNED,
        None,
        config.passport.inference.required_labels,
        "arguments",
        argument_binding_hash(arguments),
        data_class,
        assessment.level,
        risk_assessment_binding_hash(assessment),
    )


class DelegationGate:
    def __init__(self, resolve, adapter, decisions, leases, audit):
        self.resolve = resolve
        self.adapter = adapter
        self.decisions = decisions
        self.leases = leases
        self.audit = audit
        self.scope = resolve().scope

    def _policy(self, config, tool, arguments, data_class):
        if not self._boundary_error(config):
            validate_payload(tool.input_schema, arguments)
        assessment = classify(tool, arguments)
        if tool.annotation_provenance == "unavailable" and not assessment.requires_single_use_lease:
            assessment = RiskAssessment(
                RiskLevel.UNKNOWN, True, ("annotations_unavailable",), assessment.evidence
            )
        decision = evaluate(
            config.passport,
            tool,
            data_class,
            risk_assessment=assessment,
            remote_calls_enabled=config.features.remote_calls,
        )
        return assessment, decision

    def _boundary_error(self, config):
        if config.transport.type != "uds" and not getattr(
            self.adapter, "transport_verified", False
        ):
            return "unverified_route"
        if (
            not self.adapter.risk_metadata_verified
            and getattr(self.adapter, "observation_contract", None) != "sam-describe/v1"
        ):
            return "risk_metadata_unavailable"
        if self.decisions.disabled(config.scope):
            return "emergency_disconnected"
        return None

    async def preflight(self, peer_id, tool_name, arguments, data_class):
        started = time.monotonic()
        try:
            return await self._preflight(peer_id, tool_name, arguments, data_class)
        except asyncio.CancelledError as exc:
            try:
                self._audit(
                    self.resolve(), None, None, DataClass.PUBLIC, "cancellation", started=started
                )
            except Exception:
                exc.add_note("sam_audit_failed")
            raise
        except Exception:
            try:
                self._audit(
                    self.resolve(),
                    None,
                    None,
                    DataClass.PUBLIC,
                    "denial",
                    "preflight_denied",
                    started=started,
                )
            except Exception:
                pass
            raise

    async def _preflight(self, peer_id, tool_name, arguments, data_class):
        if not isinstance(data_class, DataClass) or type(arguments) is not dict:
            raise DecisionError("invalid_arguments")
        arguments = copy_plain_json(arguments)
        if len(json.dumps(arguments).encode()) > 16384:
            raise DecisionError("arguments_too_large")
        started = time.monotonic()
        config = self.resolve()
        if self.decisions.disabled(config.scope):
            raise DecisionError("emergency_disconnected")
        # Describe accepts identity only, never the sensitive payload.
        tool = await self.adapter.describe(peer_id, tool_name)
        if tool.peer_id != peer_id or tool.canonical_uri != tool_name:
            raise DecisionError("destination_changed")
        assessment, policy = self._policy(config, tool, arguments, data_class)
        error = self._boundary_error(config)
        outcome = "deny" if error else policy.outcome
        request = binding(config, tool, arguments, data_class, assessment)
        payload = dict(
            peer_id=peer_id,
            tool_name=tool_name,
            arguments=arguments,
            data_class=data_class.value,
            binding=request.binding_hash(),
            route=route_hash(config),
            labels=list(tool.labels),
            lease_id=None,
            outcome=outcome,
            request=asdict(request),
        )
        payload = json.loads(json.dumps(payload))
        identifier = self.decisions.create(config.scope, payload)
        try:
            self._audit(
                config,
                identifier,
                assessment,
                data_class,
                "preflight",
                payload=payload,
                started=started,
            )
        except Exception:
            self.decisions.invalidate(config.scope, identifier)
            raise DecisionError("audit_storage_unavailable") from None
        return PreflightDecision(
            identifier,
            config.scope,
            config.passport.version_hash(),
            peer_id,
            tool.service,
            tool,
            (),
            data_class,
            assessment.level,
            assessment.evidence,
            RouteMode.PINNED,
            policy.required_labels,
            assessment.requires_single_use_lease,
            outcome,
            (error,) if error else policy.reasons,
            timestamp_text(self.decisions.storage.now() + timedelta(seconds=300)),
        )

    def approve(self, decision_id, *, approver_id):
        started = time.monotonic()
        try:
            return self._approve(decision_id, approver_id=approver_id)
        except Exception:
            try:
                self._audit(
                    self.resolve(),
                    decision_id,
                    None,
                    DataClass.PUBLIC,
                    "denial",
                    "approval_denied",
                    started=started,
                )
            except Exception:
                pass
            raise

    def _approve(self, decision_id, *, approver_id):
        """Trusted future authenticated API only. Never exported as a model tool."""
        config = self.resolve()
        payload = self.decisions.load(config.scope, decision_id)
        if self._boundary_error(config) or payload["outcome"] != "needs_approval":
            raise DecisionError("policy_denied")
        if payload.get("lease_id"):
            raise DecisionError("already_approved")
        # Approval uses the server's original exact request, never caller-supplied authority.
        values = dict(payload["request"])
        values["scope"] = Scope(**values["scope"])
        values["route_mode"] = RouteMode(values["route_mode"])
        values["data_class"] = DataClass(values["data_class"])
        values["risk_level"] = RiskLevel(values["risk_level"])
        values["required_labels"] = tuple(values["required_labels"])
        request = LeaseRequest(**values)
        if (
            request.binding_hash() != payload["binding"]
            or request.scope != config.scope
            or request.passport_hash != config.passport.version_hash()
            or payload["route"] != route_hash(config)
        ):
            raise DecisionError("new_preflight_required")
        lease = self.leases.issue(
            request,
            min(300, config.passport.limits.approval_lease_minutes * 60),
            1,
            approver_id=approver_id,
        )
        payload["lease_id"] = lease.id
        self._audit(config, decision_id, None, request.data_class, "approval", payload=payload)
        self.decisions.update(config.scope, decision_id, payload)

    def emergency_disconnect(self):
        scope = self.scope
        state = self.decisions.revoke_scope(scope)
        self.leases.revoke_scope(scope)
        return state

    def _audit(
        self,
        config,
        identifier,
        assessment,
        data_class,
        outcome,
        error=None,
        *,
        payload=None,
        started=None,
    ):
        payload = payload or {}
        request = payload.get("request", {})
        risk = assessment.level if assessment else RiskLevel(request.get("risk_level", "unknown"))
        latency = 0 if started is None else min(86400000, int((time.monotonic() - started) * 1000))
        self.audit.append(
            AuditEvent(
                config.scope,
                "remote_call",
                payload.get("tool_name"),
                identifier,
                payload.get("lease_id"),
                risk,
                data_class,
                RouteMode.PINNED,
                outcome,
                latency,
                0,
                error,
                {"execution_uncertain": outcome == "ambiguity"},
            )
        )

    async def invoke(self, decision_id):
        config = self.resolve()
        claimed = False
        dispatched = False
        degraded = []
        cancellation = None
        payload = {}
        started = time.monotonic()

        def result(code=None, *, uncertain=False, **kwargs):
            uncertain = uncertain or code == "duplicate_execution_possible"
            if code:
                try:
                    self._audit(
                        config,
                        decision_id,
                        None,
                        DataClass(payload.get("data_class", "public")),
                        "ambiguity" if uncertain else "denial",
                        code,
                        payload=payload,
                        started=started,
                    )
                except Exception:
                    degraded.append("audit_failed")
            return ToolResult(
                code,
                degraded=degraded,
                admitted=dispatched,
                execution_uncertain=uncertain,
                **kwargs,
            )

        try:
            error = self._boundary_error(config)
            if error:
                return result(error)
            payload = self.decisions.load(config.scope, decision_id)
            try:
                tool = await self.adapter.describe(payload["peer_id"], payload["tool_name"])
            except (SamSchemaError, ValueError, TypeError):
                self.decisions.invalidate(config.scope, decision_id)
                return result("schema_changed")
            observed = payload["request"]
            if (
                tool.schema_hash != observed["schema_hash"]
                or tool.risk_metadata_hash() != observed["risk_metadata_hash"]
                or tool.peer_id != observed["peer_id"]
                or tool.service != observed["service"]
                or tool.canonical_uri != observed["canonical_uri"]
                or list(tool.labels) != payload["labels"]
            ):
                self.decisions.invalidate(config.scope, decision_id)
                return result("schema_or_boundary_changed")
            # Re-resolve after the last awaited network operation, immediately before dispatch.
            config = self.resolve()
            if (
                config.scope != self.scope
                or route_hash(config) != payload["route"]
                or config.passport.version_hash() != observed["passport_hash"]
            ):
                self.decisions.invalidate(self.scope, decision_id)
                return result("schema_or_boundary_changed")
            data_class = DataClass(payload["data_class"])
            arguments = payload["arguments"]
            try:
                assessment, policy = self._policy(config, tool, arguments, data_class)
            except DecisionError as exc:
                if str(exc) == "unsupported_schema":
                    self.decisions.invalidate(config.scope, decision_id)
                raise
            request = binding(config, tool, arguments, data_class, assessment)
            if (
                request.binding_hash() != payload["binding"]
                or route_hash(config) != payload["route"]
                or list(tool.labels) != payload["labels"]
            ):
                self.decisions.invalidate(config.scope, decision_id)
                return result("schema_or_boundary_changed")
            error = self._boundary_error(config)
            if error or policy.outcome == "deny" or payload["outcome"] == "deny":
                return result(error or "policy_denied")
            if policy.outcome == "needs_approval" and not payload["lease_id"]:
                return result("approval_required")
            self.decisions.claim(
                config.scope, decision_id, config.passport.limits.calls_per_session, payload
            )
            claimed = True
            if policy.outcome == "needs_approval" or assessment.requires_single_use_lease:
                consumed = self.leases.consume(payload["lease_id"], request)
                if not consumed.allowed:
                    return result(consumed.reason)
            try:
                self._audit(
                    config,
                    decision_id,
                    assessment,
                    data_class,
                    "dispatch",
                    payload=payload,
                    started=started,
                )
            except Exception:
                return result("audit_storage_unavailable")
            self.decisions.admit(config.scope, decision_id, payload)
            dispatched = True
            async with asyncio.timeout(config.passport.limits.timeout_seconds):
                remote_result = await self.adapter.call(
                    tool, arguments, policy.required_labels_wire
                )
            # Raw remote content is deliberately not inserted in model history here.
            # Read-only public output uses the bounded inspector owned by native_tools.
            from .tool_output import inspect_result

            content = inspect_result(remote_result, arguments, config.transport.token, data_class)
            try:
                self._audit(
                    config,
                    decision_id,
                    assessment,
                    data_class,
                    "success",
                    payload=payload,
                    started=started,
                )
            except Exception:
                degraded.append("audit_failed")
            return result(content=content)
        except DecisionError as exc:
            return result(str(exc))
        except (SamAuthRequired, SamAuthRejected, SamPolicyDenied) as exc:
            codes = {
                SamAuthRequired: "auth_required",
                SamAuthRejected: "auth_rejected",
                SamPolicyDenied: "policy_denied",
            }
            return result(codes[type(exc)])
        except SamSchemaError:
            return result("schema_changed", uncertain=dispatched)
        except SamCallAmbiguous:
            return result("duplicate_execution_possible")
        except asyncio.CancelledError as exc:
            cancellation = exc
            try:
                self._audit(
                    config,
                    decision_id,
                    None,
                    DataClass(payload.get("data_class", "public")),
                    "cancellation",
                    payload=payload,
                    started=started,
                )
            except Exception:
                exc.add_note("sam_audit_failed")
            raise
        except (SamError, TimeoutError):
            return result(
                "duplicate_execution_possible" if dispatched else "destination_unavailable"
            )
        except Exception:
            return result("duplicate_execution_possible" if dispatched else "gate_unavailable")
        finally:
            if claimed:
                try:
                    self.decisions.finish(config.scope, decision_id)
                except Exception:
                    degraded.append("cleanup_failed")
                    if cancellation is not None:
                        cancellation.add_note("sam_cleanup_failed")
