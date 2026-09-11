"""Server-owned review and offline controls; no payload or lease bearer responses."""

from .audit import AuditEvent
from .decisions import DecisionError
from .domain import DataClass, RiskLevel, RouteMode


def _control_audit(audit, scope, outcome):
    audit.append(
        AuditEvent(
            scope,
            "control",
            None,
            None,
            None,
            RiskLevel.UNKNOWN,
            DataClass.PUBLIC,
            RouteMode.PINNED,
            outcome,
            0,
            0,
            None,
            {},
        )
    )


def review_decision(decisions, scope, identifier):
    payload = decisions.load(scope, identifier)
    request = payload["request"]
    return {
        "decision_id": identifier,
        "peer_id": payload["peer_id"],
        "tool_name": payload["tool_name"],
        "data_class": payload["data_class"],
        "risk_level": request["risk_level"],
        "schema_hash": request["schema_hash"],
        "argument_hash": request["boundary_hash"],
        "route_mode": request["route_mode"],
        "required_labels": request["required_labels"],
        "label_semantics": "any_of",
        "expires_us": payload["_expires_us"],
        "outcome": payload["outcome"],
        "approved": bool(payload.get("lease_id")),
        "single_use": True,
        "duplicate_execution_possible": True,
        "kind": payload.get("kind", "remote_tool"),
    }


def approve_decision(gate, identifier, acknowledgment, approver):
    if acknowledgment != "APPROVE":
        raise DecisionError("acknowledgment_required")
    gate.approve(identifier, approver_id=approver)
    return {"approved": True, "decision_id": identifier, "single_use": True}


def stop_scope(scope, stores):
    decisions, leases, _audit = stores
    state = decisions.revoke_scope(scope)
    degraded = []
    try:
        leases.revoke_profile(scope)
    except Exception:
        # The durable dispatch barrier is already closed even if lease storage fails.
        degraded.append("lease_storage_unavailable")
    try:
        _control_audit(_audit, scope, "disconnected")
    except Exception:
        degraded.append("audit_failed")
    return dict(state, stopped=True, status="verified_now", degraded=degraded)


def resume_scope(scope, stores, acknowledgment):
    if acknowledgment != "RESUME":
        raise DecisionError("acknowledgment_required")
    decisions, leases, audit = stores
    leases.revoke_profile(scope)
    _control_audit(audit, scope, "resume_requested")
    return dict(decisions.resume_scope(scope), status="verified_now")
