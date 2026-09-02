"""Capability Passport evaluation for guarded SAM tool invocation."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Literal

from .domain import (
    CapabilityPassport,
    DataClass,
    OperatingMode,
    RiskLevel,
    ToolDescriptor,
    validate_required_label,
)
from .risk import RiskAssessment, classify


@dataclass(frozen=True)
class PassportDecision:
    """Stable policy result consumed verbatim by preflight and lease binding."""

    outcome: Literal["allow", "deny", "needs_approval"]
    reasons: tuple[str, ...]
    evidence: tuple[str, ...]
    risk_level: RiskLevel
    data_class: DataClass
    required_labels: tuple[str, ...]
    required_labels_wire: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "required_labels_wire",
            serialize_required_labels(self.required_labels),
        )


_DATA_CLASS_ORDER = {
    DataClass.PUBLIC: 0,
    DataClass.INTERNAL: 1,
    DataClass.CONFIDENTIAL: 2,
    DataClass.REGULATED: 3,
}
_GUARDED_INVOCATION_MODES = {
    OperatingMode.GUARDED_MESH,
    OperatingMode.EMBASSY,
    OperatingMode.SOVEREIGN,
}
_MUTATION_RISKS = {
    RiskLevel.MUTATION,
    RiskLevel.DESTRUCTIVE,
    RiskLevel.FINANCIAL,
    RiskLevel.CREDENTIAL,
}


def serialize_required_labels(labels: tuple[str, ...]) -> str:
    """Serialize immutable any-of labels exactly once for SAM's wire contract."""
    if not isinstance(labels, tuple):
        raise TypeError("required labels must be an immutable tuple")
    return ",".join(validate_required_label(label) for label in labels)


def _decision(
    passport: CapabilityPassport,
    data_class: DataClass,
    risk_level: RiskLevel,
    outcome: Literal["allow", "deny", "needs_approval"],
    reason: str,
    evidence: tuple[str, ...] = (),
) -> PassportDecision:
    return PassportDecision(
        outcome=outcome,
        reasons=(reason,),
        evidence=evidence,
        risk_level=risk_level,
        data_class=data_class,
        required_labels=passport.inference.required_labels,
    )


def evaluate(
    passport: CapabilityPassport,
    descriptor: ToolDescriptor,
    data_class: DataClass,
    *,
    risk_assessment: RiskAssessment | None = None,
    remote_calls_enabled: bool = False,
) -> PassportDecision:
    """Evaluate fail-closed passport precedence against the canonical URI."""
    descriptive_risk = risk_assessment or classify(descriptor, {})
    uri = descriptor.canonical_uri

    deny_rule = next(
        (pattern for pattern in passport.outbound.deny_tools if fnmatchcase(uri, pattern)),
        None,
    )
    if deny_rule is not None:
        return _decision(
            passport,
            data_class,
            descriptive_risk.level,
            "deny",
            "explicit_deny",
            (f"deny_rule:{deny_rule}",),
        )

    maximum = passport.outbound.max_data_class
    if _DATA_CLASS_ORDER[data_class] > _DATA_CLASS_ORDER[maximum]:
        return _decision(
            passport,
            data_class,
            descriptive_risk.level,
            "deny",
            "data_class_ceiling_exceeded",
            (f"data_class:{data_class.value}", f"max_data_class:{maximum.value}"),
        )

    if passport.mode not in _GUARDED_INVOCATION_MODES:
        return _decision(
            passport,
            data_class,
            descriptive_risk.level,
            "deny",
            "mode_blocks_guarded_invocation",
            (f"mode:{passport.mode.value}",),
        )

    if remote_calls_enabled is not True:
        return _decision(
            passport,
            data_class,
            descriptive_risk.level,
            "deny",
            "remote_calls_disabled",
        )

    if risk_assessment is None:
        return _decision(
            passport,
            data_class,
            descriptive_risk.level,
            "deny",
            "risk_assessment_required",
        )
    if not isinstance(risk_assessment, RiskAssessment):
        raise TypeError("risk_assessment must be a RiskAssessment")

    allow_rule = next(
        (pattern for pattern in passport.outbound.allow_services if fnmatchcase(uri, pattern)),
        None,
    )
    if allow_rule is None:
        return _decision(
            passport,
            data_class,
            risk_assessment.level,
            "deny",
            "not_explicitly_allowed",
        )

    mutation_policy = passport.outbound.remote_mutations
    if risk_assessment.level in _MUTATION_RISKS and mutation_policy == "deny":
        return _decision(
            passport,
            data_class,
            risk_assessment.level,
            "deny",
            "remote_mutations_denied",
            risk_assessment.evidence,
        )

    allow_evidence = (f"allow_rule:{allow_rule}",)
    if risk_assessment.requires_single_use_lease:
        return _decision(
            passport,
            data_class,
            risk_assessment.level,
            "needs_approval",
            "single_use_lease_required",
            allow_evidence + risk_assessment.evidence,
        )

    if risk_assessment.level is RiskLevel.NETWORK:
        return _decision(
            passport,
            data_class,
            risk_assessment.level,
            "needs_approval",
            "risk_approval_required",
            allow_evidence + risk_assessment.evidence,
        )

    return _decision(
        passport,
        data_class,
        risk_assessment.level,
        "allow",
        "explicit_allow",
        allow_evidence,
    )
