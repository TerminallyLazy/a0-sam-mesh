"""Exact, server-owned approval leases for guarded SAM operations."""

from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from .domain import DataClass, RiskLevel, RouteMode, Scope, validate_required_label
from .risk import RiskAssessment
from .storage import (
    SQLiteStorage,
    StorageUnavailableError,
    canonical_hash,
    timestamp_text,
    timestamp_us,
    validate_scope,
)

LEASE_SCHEMA = "a0.sam.lease/v1alpha1"
_HASH = re.compile(r"[0-9a-f]{64}")
_SINGLE_USE_RISKS = {
    RiskLevel.MUTATION,
    RiskLevel.DESTRUCTIVE,
    RiskLevel.FINANCIAL,
    RiskLevel.CREDENTIAL,
    RiskLevel.UNKNOWN,
}
_MAX_TTL_SECONDS = 86_400
_MAX_USES = 1_000
_CONSUME_REASONS = {
    "lease_consumed",
    "lease_not_found",
    "lease_revoked",
    "lease_binding_mismatch",
    "lease_expired",
    "lease_exhausted",
    "lease_storage_unavailable",
}


class LeaseStorageError(RuntimeError):
    """Lease state could not be accessed safely."""


def _exact_string(value: object, name: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if type(value) is not str or not value or len(value.encode("utf-8")) > 4_096:
        raise ValueError(f"{name} must be a bounded nonempty string")
    return value


def _hash(value: object, name: str) -> str:
    if type(value) is not str or not _HASH.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True)
class LeaseRequest:
    """Complete authority binding required to issue or consume a lease."""

    scope: Scope
    peer_id: str
    service: str
    canonical_uri: str
    schema_hash: str
    risk_metadata_hash: str
    passport_hash: str
    route_mode: RouteMode
    model: str | None
    required_labels: tuple[str, ...]
    boundary_kind: Literal["arguments", "data_boundary"]
    boundary_hash: str
    data_class: DataClass
    risk_level: RiskLevel
    risk_assessment_hash: str

    def __post_init__(self) -> None:
        validate_scope(self.scope)
        for name in ("peer_id", "service", "canonical_uri"):
            _exact_string(getattr(self, name), name)
        for name in (
            "schema_hash",
            "risk_metadata_hash",
            "passport_hash",
            "boundary_hash",
            "risk_assessment_hash",
        ):
            _hash(getattr(self, name), name)
        if not isinstance(self.route_mode, RouteMode):
            raise TypeError("route_mode must be a RouteMode")
        _exact_string(self.model, "model", optional=True)
        if type(self.required_labels) is not tuple:
            raise TypeError("required_labels must be an exact tuple")
        labels = tuple(validate_required_label(label) for label in self.required_labels)
        if (
            len(labels) > 64
            or len(labels) != len(set(labels))
            or any(len(label.encode("utf-8")) > 512 for label in labels)
        ):
            raise ValueError("required_labels must be bounded and unique")
        if self.boundary_kind not in {"arguments", "data_boundary"}:
            raise ValueError("boundary_kind must identify the bound payload type")
        if not isinstance(self.data_class, DataClass):
            raise TypeError("data_class must be a DataClass")
        if not isinstance(self.risk_level, RiskLevel):
            raise TypeError("risk_level must be a RiskLevel")

    def binding_payload(self) -> dict[str, Any]:
        return {
            "schema": LEASE_SCHEMA,
            "scope": {
                "project": self.scope.project_name,
                "profile": self.scope.agent_profile,
                "chat": self.scope.chat_id,
            },
            "peer_id": self.peer_id,
            "service": self.service,
            "canonical_uri": self.canonical_uri,
            "schema_hash": self.schema_hash,
            "risk_metadata_hash": self.risk_metadata_hash,
            "passport_hash": self.passport_hash,
            "route_mode": self.route_mode.value,
            "model": self.model,
            "required_labels": list(self.required_labels),
            "boundary": {"kind": self.boundary_kind, "hash": self.boundary_hash},
            "data_class": self.data_class.value,
            "risk_level": self.risk_level.value,
            "risk_assessment_hash": self.risk_assessment_hash,
        }

    def binding_hash(self) -> str:
        return canonical_hash(
            self.binding_payload(),
            domain="a0.sam.lease.binding/v1alpha1",
        )


@dataclass(frozen=True)
class ApprovalLease:
    """Trusted server response; the raw opaque ID is always repr-redacted."""

    id: str = field(repr=False)
    request: LeaseRequest
    issued_at: datetime
    expires_at: datetime
    max_uses: int
    uses: int
    approver_id: str | None = None
    schema: str = LEASE_SCHEMA

    def __post_init__(self) -> None:
        if type(self.id) is not str or len(self.id) < 40:
            raise ValueError("lease ID is invalid")
        if not isinstance(self.request, LeaseRequest):
            raise TypeError("request must be a LeaseRequest")
        if type(self.max_uses) is not int or self.max_uses < 1:
            raise ValueError("max_uses must be positive")
        if type(self.uses) is not int or not 0 <= self.uses <= self.max_uses:
            raise ValueError("uses is invalid")
        for value, name in (
            (self.issued_at, "issued_at"),
            (self.expires_at, "expires_at"),
        ):
            if not isinstance(value, datetime) or value.tzinfo is None:
                raise ValueError(f"{name} must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be later than issued_at")
        _exact_string(self.approver_id, "approver_id", optional=True)


@dataclass(frozen=True)
class LeaseConsumeResult:
    allowed: bool
    reason: Literal[
        "lease_consumed",
        "lease_not_found",
        "lease_revoked",
        "lease_binding_mismatch",
        "lease_expired",
        "lease_exhausted",
        "lease_storage_unavailable",
    ]
    uses: int | None = None
    max_uses: int | None = None

    def __post_init__(self) -> None:
        if type(self.allowed) is not bool:
            raise TypeError("allowed must be a boolean")
        if self.reason not in _CONSUME_REASONS:
            raise ValueError("unknown lease result reason")
        if self.allowed is not (self.reason == "lease_consumed"):
            raise ValueError("lease result reason conflicts with allowed state")
        for value in (self.uses, self.max_uses):
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError("lease result counters must be nonnegative integers or null")
        if self.uses is not None and self.max_uses is not None and self.uses > self.max_uses:
            raise ValueError("lease result uses cannot exceed max_uses")


def argument_binding_hash(
    value: Any,
    *,
    boundary_kind: Literal["arguments", "data_boundary"] = "arguments",
) -> str:
    if boundary_kind not in {"arguments", "data_boundary"}:
        raise ValueError("invalid boundary kind")
    return canonical_hash(
        {"kind": boundary_kind, "value": value},
        domain="a0.sam.lease.argument-boundary/v1alpha1",
    )


def risk_assessment_binding_hash(assessment: RiskAssessment) -> str:
    if not isinstance(assessment, RiskAssessment):
        raise TypeError("assessment must be a RiskAssessment")
    return canonical_hash(
        {
            "level": assessment.level.value,
            "requires_single_use_lease": assessment.requires_single_use_lease,
            "reasons": list(assessment.reasons),
            "evidence": list(assessment.evidence),
        },
        domain="a0.sam.lease.risk-assessment/v1alpha1",
    )


class LeaseStore:
    """SQLite lease store with one short-lived connection per operation."""

    def __init__(self, *, db_path: str | Path | None = None, clock=None) -> None:
        options = {"db_path": db_path}
        if clock is not None:
            options["clock"] = clock
        self._storage = SQLiteStorage(**options)

    @staticmethod
    def _initialize(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS leases (
                lease_digest TEXT PRIMARY KEY,
                project TEXT NOT NULL,
                profile TEXT NOT NULL,
                chat TEXT NOT NULL,
                binding_hash TEXT NOT NULL,
                issued_at_us INTEGER NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at_us INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                max_uses INTEGER NOT NULL CHECK(max_uses > 0),
                use_count INTEGER NOT NULL DEFAULT 0 CHECK(use_count >= 0),
                revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
                revoked_at TEXT,
                approver_id TEXT
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS leases_scope_idx "
            "ON leases(project, profile, chat, revoked)"
        )

    def issue(
        self,
        request: LeaseRequest,
        ttl_seconds: int,
        max_uses: int,
        approver_id: str | None = None,
    ) -> ApprovalLease:
        if not isinstance(request, LeaseRequest):
            raise TypeError("request must be a LeaseRequest")
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= _MAX_TTL_SECONDS:
            raise ValueError("ttl_seconds must be between 1 and 86400")
        if type(max_uses) is not int or not 1 <= max_uses <= _MAX_USES:
            raise ValueError("max_uses must be between 1 and 1000")
        if request.risk_level in _SINGLE_USE_RISKS and max_uses != 1:
            raise ValueError("this risk level requires an exact single-use lease")
        approver = _exact_string(approver_id, "approver_id", optional=True)
        issued_at = self._storage.now()
        expires_at = issued_at + timedelta(seconds=ttl_seconds)
        raw_id = secrets.token_urlsafe(32)
        lease_digest = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()
        try:
            connection = self._storage.connect(request.scope)
            try:
                self._initialize(connection)
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO leases (
                        lease_digest, project, profile, chat, binding_hash,
                        issued_at_us, issued_at, expires_at_us, expires_at,
                        max_uses, use_count, revoked, approver_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
                    """,
                    (
                        lease_digest,
                        request.scope.project_name,
                        request.scope.agent_profile,
                        request.scope.chat_id,
                        request.binding_hash(),
                        timestamp_us(issued_at),
                        timestamp_text(issued_at),
                        timestamp_us(expires_at),
                        timestamp_text(expires_at),
                        max_uses,
                        approver,
                    ),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except (StorageUnavailableError, sqlite3.Error):
            raise LeaseStorageError("lease_storage_unavailable") from None
        return ApprovalLease(
            id=raw_id,
            request=request,
            issued_at=issued_at,
            expires_at=expires_at,
            max_uses=max_uses,
            uses=0,
            approver_id=approver,
        )

    def consume(self, lease_id: str, request: LeaseRequest) -> LeaseConsumeResult:
        if type(lease_id) is not str or not lease_id:
            return LeaseConsumeResult(False, "lease_not_found")
        if not isinstance(request, LeaseRequest):
            raise TypeError("request must be a LeaseRequest")
        lease_digest = hashlib.sha256(lease_id.encode("utf-8")).hexdigest()
        try:
            connection = self._storage.connect(request.scope)
            try:
                self._initialize(connection)
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM leases WHERE lease_digest = ?",
                    (lease_digest,),
                ).fetchone()
                if row is None:
                    result = LeaseConsumeResult(False, "lease_not_found")
                elif row["revoked"]:
                    result = LeaseConsumeResult(False, "lease_revoked")
                elif row["binding_hash"] != request.binding_hash():
                    result = LeaseConsumeResult(False, "lease_binding_mismatch")
                elif timestamp_us(self._storage.now()) >= row["expires_at_us"]:
                    result = LeaseConsumeResult(False, "lease_expired")
                elif row["use_count"] >= row["max_uses"]:
                    result = LeaseConsumeResult(
                        False,
                        "lease_exhausted",
                        row["use_count"],
                        row["max_uses"],
                    )
                else:
                    uses = row["use_count"] + 1
                    connection.execute(
                        "UPDATE leases SET use_count = ? WHERE lease_digest = ?",
                        (uses, lease_digest),
                    )
                    result = LeaseConsumeResult(
                        True,
                        "lease_consumed",
                        uses,
                        row["max_uses"],
                    )
                connection.commit()
                return result
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except (StorageUnavailableError, sqlite3.Error):
            return LeaseConsumeResult(False, "lease_storage_unavailable")

    def revoke_scope(self, scope: Scope) -> int:
        validated = validate_scope(scope)
        try:
            connection = self._storage.connect(validated)
            try:
                self._initialize(connection)
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    """
                    UPDATE leases SET revoked = 1, revoked_at = ?
                    WHERE project = ? AND profile = ? AND chat = ? AND revoked = 0
                    """,
                    (
                        timestamp_text(self._storage.now()),
                        validated.project_name,
                        validated.agent_profile,
                        validated.chat_id,
                    ),
                )
                connection.commit()
                return cursor.rowcount
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except (StorageUnavailableError, sqlite3.Error):
            raise LeaseStorageError("lease_storage_unavailable") from None
