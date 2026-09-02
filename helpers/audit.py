"""Redacted, scope-partitioned, integrity-chained SAM Mesh audit storage."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .domain import DataClass, RiskLevel, RouteMode, Scope
from .storage import (
    ZERO_HASH,
    SQLiteStorage,
    StorageUnavailableError,
    canonical_json_bytes,
    copy_plain_json,
    digest_alias,
    timestamp_text,
    timestamp_us,
    validate_scope,
)

AUDIT_SCHEMA = "a0.sam.audit/v1alpha1"
_REDACTED = "[REDACTED]"
_SECRET_KEY = re.compile(
    r"token|secret|password|authorization|cookie|credential",
    re.IGNORECASE,
)
_EVENT_TYPE = re.compile(r"[a-z][a-z0-9_.:-]{0,63}")
_ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_MAX_EVENTS = 10_000
_MAX_AGE = timedelta(days=30)
_MAX_LIST_LIMIT = 1_000
_HASH = re.compile(r"[0-9a-f]{64}")
_VERIFY_REASONS = {
    "audit_chain_valid",
    "audit_storage_unavailable",
    "audit_head_mismatch",
    "audit_count_mismatch",
    "audit_sequence_mismatch",
    "audit_scope_mismatch",
    "audit_prev_hash_mismatch",
    "audit_payload_mismatch",
    "audit_hash_mismatch",
}


class AuditStorageError(RuntimeError):
    """Audit state could not be accessed safely."""


def _bounded_string(
    value: object,
    name: str,
    *,
    optional: bool = False,
    maximum: int = 4_096,
) -> str | None:
    if optional and value is None:
        return None
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{name} must be a bounded nonempty string")
    return value


def _freeze_json(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze_json(item) for item in value)
    return value


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_plain_json(item) for item in value]
    return value


def _validate_sensitive_paths(value: object) -> tuple[tuple[str, ...], ...]:
    if type(value) is not tuple or len(value) > 64:
        raise TypeError("sensitive_paths must be a bounded tuple")
    parsed: list[tuple[str, ...]] = []
    for item in value:
        if type(item) is not str or not item or item != item.strip():
            raise ValueError("sensitive paths must be exact dotted paths")
        parts = tuple(item.split("."))
        if any(not part or len(part.encode("utf-8")) > 256 for part in parts):
            raise ValueError("sensitive paths must be exact dotted paths")
        parsed.append(parts)
    if len(parsed) != len(set(parsed)):
        raise ValueError("sensitive paths must be unique")
    return tuple(parsed)


@dataclass(frozen=True)
class AuditEvent:
    """Validated input event; server-generated fields are deliberately absent."""

    scope: Scope
    event_type: str
    destination: str | None = field(repr=False)
    decision_id: str | None = field(repr=False)
    lease_id: str | None = field(repr=False)
    risk_level: RiskLevel
    data_class: DataClass
    route_mode: RouteMode
    outcome: str
    latency_ms: int | None
    retry_count: int
    error_code: str | None
    details: Mapping[str, Any] = field(repr=False)
    sensitive_paths: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        validate_scope(self.scope)
        if type(self.event_type) is not str or not _EVENT_TYPE.fullmatch(self.event_type):
            raise ValueError("event_type must be a bounded safe identifier")
        _bounded_string(self.destination, "destination", optional=True)
        _bounded_string(self.decision_id, "decision_id", optional=True)
        _bounded_string(self.lease_id, "lease_id", optional=True)
        if not isinstance(self.risk_level, RiskLevel):
            raise TypeError("risk_level must be a RiskLevel")
        if not isinstance(self.data_class, DataClass):
            raise TypeError("data_class must be a DataClass")
        if not isinstance(self.route_mode, RouteMode):
            raise TypeError("route_mode must be a RouteMode")
        _bounded_string(self.outcome, "outcome", maximum=128)
        if self.latency_ms is not None and (
            type(self.latency_ms) is not int or not 0 <= self.latency_ms <= 86_400_000
        ):
            raise ValueError("latency_ms must be a bounded nonnegative integer or null")
        if type(self.retry_count) is not int or not 0 <= self.retry_count <= 1_000:
            raise ValueError("retry_count must be a bounded nonnegative integer")
        if self.error_code is not None and (
            type(self.error_code) is not str or not _ERROR_CODE.fullmatch(self.error_code)
        ):
            raise ValueError("error_code must be a bounded safe identifier or null")
        if type(self.details) is not dict:
            raise TypeError("details must be a plain JSON object")
        details = copy_plain_json(self.details, "details")
        paths = _validate_sensitive_paths(self.sensitive_paths)
        object.__setattr__(self, "details", _freeze_json(details))
        object.__setattr__(self, "sensitive_paths", tuple(".".join(path) for path in paths))


@dataclass(frozen=True)
class AuditAppendResult:
    sequence: int
    event_hash: str
    timestamp: str

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("sequence must be a positive integer")
        if type(self.event_hash) is not str or not _HASH.fullmatch(self.event_hash):
            raise ValueError("event_hash must be a lowercase SHA-256 digest")
        if type(self.timestamp) is not str or not self.timestamp.endswith("Z"):
            raise ValueError("timestamp must be a UTC timestamp")


@dataclass(frozen=True)
class AuditVerifyResult:
    valid: bool
    reason: str
    base_sequence: int
    head_sequence: int
    retained_count: int

    def __post_init__(self) -> None:
        if type(self.valid) is not bool:
            raise TypeError("valid must be a boolean")
        if type(self.reason) is not str or not _ERROR_CODE.fullmatch(self.reason):
            raise ValueError("reason must be a bounded safe identifier")
        if self.reason not in _VERIFY_REASONS:
            raise ValueError("unknown audit verification reason")
        if self.valid is not (self.reason == "audit_chain_valid"):
            raise ValueError("audit verification reason conflicts with valid state")
        for value in (self.base_sequence, self.head_sequence, self.retained_count):
            if type(value) is not int or value < 0:
                raise ValueError("verification counters must be nonnegative integers")
        if self.base_sequence > self.head_sequence:
            raise ValueError("base_sequence cannot exceed head_sequence")


def _redact(value: Any, sensitive: set[tuple[str, ...]], path: tuple[str, ...] = ()) -> Any:
    if type(value) is dict:
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            item_path = path + (key,)
            if _SECRET_KEY.search(key) or item_path in sensitive:
                redacted[key] = _REDACTED
            else:
                redacted[key] = _redact(item, sensitive, item_path)
        return redacted
    if type(value) is list:
        return [_redact(item, sensitive, path + (str(index),)) for index, item in enumerate(value)]
    return value


def _chain_hash(payload: dict[str, Any], previous_hash: str) -> str:
    framed = (
        b"a0.sam.audit.chain/v1alpha1\x00"
        + previous_hash.encode("ascii")
        + b"\x00"
        + canonical_json_bytes(payload, domain="a0.sam.audit.event/v1alpha1")
    )
    return hashlib.sha256(framed).hexdigest()


def _scope_values(scope: Scope) -> tuple[str, str, str]:
    return scope.project_name, scope.agent_profile, scope.chat_id


class AuditStore:
    """Append and verify redacted events using short-lived SQLite connections."""

    def __init__(self, *, db_path: str | Path | None = None, clock=None) -> None:
        options = {"db_path": db_path}
        if clock is not None:
            options["clock"] = clock
        self._storage = SQLiteStorage(**options)

    @staticmethod
    def _initialize(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_heads (
                project TEXT NOT NULL,
                profile TEXT NOT NULL,
                chat TEXT NOT NULL,
                base_sequence INTEGER NOT NULL,
                base_hash TEXT NOT NULL,
                head_sequence INTEGER NOT NULL,
                head_hash TEXT NOT NULL,
                retained_count INTEGER NOT NULL,
                PRIMARY KEY(project, profile, chat)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                project TEXT NOT NULL,
                profile TEXT NOT NULL,
                chat TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                occurred_at_us INTEGER NOT NULL,
                occurred_at TEXT NOT NULL,
                payload TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                PRIMARY KEY(project, profile, chat, sequence),
                FOREIGN KEY(project, profile, chat)
                    REFERENCES audit_heads(project, profile, chat)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS audit_events_retention_idx "
            "ON audit_events(project, profile, chat, occurred_at_us, sequence)"
        )

    @staticmethod
    def _read_head(connection: sqlite3.Connection, scope: Scope) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM audit_heads WHERE project = ? AND profile = ? AND chat = ?",
            _scope_values(scope),
        ).fetchone()

    @staticmethod
    def _event_payload(event: AuditEvent, sequence: int, occurred_at: str) -> dict[str, Any]:
        raw = {
            "schema": AUDIT_SCHEMA,
            "sequence": sequence,
            "timestamp": occurred_at,
            "scope": {
                "project": event.scope.project_name,
                "profile": event.scope.agent_profile,
                "chat": event.scope.chat_id,
            },
            "event_type": event.event_type,
            "destination_alias": digest_alias(
                event.destination,
                domain="a0.sam.audit.destination/v1alpha1",
                prefix="dst",
            ),
            "decision_alias": digest_alias(
                event.decision_id,
                domain="a0.sam.audit.decision/v1alpha1",
                prefix="dec",
            ),
            "lease_alias": digest_alias(
                event.lease_id,
                domain="a0.sam.audit.lease/v1alpha1",
                prefix="lea",
            ),
            "risk_level": event.risk_level.value,
            "data_class": event.data_class.value,
            "route_mode": event.route_mode.value,
            "outcome": event.outcome,
            "latency_ms": event.latency_ms,
            "retry_count": event.retry_count,
            "error_code": event.error_code,
            "details": _plain_json(event.details),
        }
        sensitive = {tuple(path.split(".")) for path in event.sensitive_paths}
        return _redact(raw, sensitive)

    @staticmethod
    def _prune(
        connection: sqlite3.Connection,
        scope: Scope,
        now_us: int,
        retained_count: int,
    ) -> tuple[int, str, int]:
        values = _scope_values(scope)
        prune_sequence = 0
        aged = connection.execute(
            """
            SELECT sequence FROM audit_events
            WHERE project = ? AND profile = ? AND chat = ? AND occurred_at_us <= ?
            ORDER BY sequence DESC LIMIT 1
            """,
            values + (now_us - int(_MAX_AGE.total_seconds() * 1_000_000),),
        ).fetchone()
        if aged is not None:
            prune_sequence = aged["sequence"]
        excess = retained_count - _MAX_EVENTS
        if excess > 0:
            counted = connection.execute(
                """
                SELECT sequence FROM audit_events
                WHERE project = ? AND profile = ? AND chat = ?
                ORDER BY sequence LIMIT 1 OFFSET ?
                """,
                values + (excess - 1,),
            ).fetchone()
            if counted is not None:
                prune_sequence = max(prune_sequence, counted["sequence"])
        if prune_sequence == 0:
            return 0, ZERO_HASH, retained_count
        anchor = connection.execute(
            """
            SELECT sequence, event_hash FROM audit_events
            WHERE project = ? AND profile = ? AND chat = ? AND sequence = ?
            """,
            values + (prune_sequence,),
        ).fetchone()
        if anchor is None:
            raise sqlite3.DatabaseError("audit retention anchor missing")
        deleted = connection.execute(
            """
            DELETE FROM audit_events
            WHERE project = ? AND profile = ? AND chat = ? AND sequence <= ?
            """,
            values + (prune_sequence,),
        ).rowcount
        return anchor["sequence"], anchor["event_hash"], retained_count - deleted

    def append(self, event: AuditEvent) -> AuditAppendResult:
        if not isinstance(event, AuditEvent):
            raise TypeError("event must be an AuditEvent")
        occurred = self._storage.now()
        occurred_text = timestamp_text(occurred)
        occurred_us = timestamp_us(occurred)
        try:
            connection = self._storage.connect(event.scope)
            try:
                self._initialize(connection)
                connection.execute("BEGIN IMMEDIATE")
                head = self._read_head(connection, event.scope)
                if head is None:
                    connection.execute(
                        """
                        INSERT INTO audit_heads (
                            project, profile, chat, base_sequence, base_hash,
                            head_sequence, head_hash, retained_count
                        ) VALUES (?, ?, ?, 0, ?, 0, ?, 0)
                        """,
                        _scope_values(event.scope) + (ZERO_HASH, ZERO_HASH),
                    )
                    sequence = 1
                    previous_hash = ZERO_HASH
                    retained_count = 0
                else:
                    sequence = head["head_sequence"] + 1
                    previous_hash = head["head_hash"]
                    retained_count = head["retained_count"]
                payload = self._event_payload(event, sequence, occurred_text)
                payload_text = json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                )
                event_hash = _chain_hash(payload, previous_hash)
                connection.execute(
                    """
                    INSERT INTO audit_events (
                        project, profile, chat, sequence, occurred_at_us,
                        occurred_at, payload, prev_hash, event_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    _scope_values(event.scope)
                    + (
                        sequence,
                        occurred_us,
                        occurred_text,
                        payload_text,
                        previous_hash,
                        event_hash,
                    ),
                )
                retained_count += 1
                base_sequence, base_hash, retained_count = self._prune(
                    connection,
                    event.scope,
                    occurred_us,
                    retained_count,
                )
                if head is not None and base_sequence == 0:
                    base_sequence = head["base_sequence"]
                    base_hash = head["base_hash"]
                connection.execute(
                    """
                    UPDATE audit_heads SET
                        base_sequence = ?, base_hash = ?, head_sequence = ?,
                        head_hash = ?, retained_count = ?
                    WHERE project = ? AND profile = ? AND chat = ?
                    """,
                    (
                        base_sequence,
                        base_hash,
                        sequence,
                        event_hash,
                        retained_count,
                    )
                    + _scope_values(event.scope),
                )
                connection.commit()
                return AuditAppendResult(sequence, event_hash, occurred_text)
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except (StorageUnavailableError, sqlite3.Error):
            raise AuditStorageError("audit_storage_unavailable") from None

    def list_redacted(self, scope: Scope, *, limit: int) -> tuple[Mapping[str, Any], ...]:
        validated = validate_scope(scope)
        if type(limit) is not int or not 1 <= limit <= _MAX_LIST_LIMIT:
            raise ValueError("limit must be between 1 and 1000")
        try:
            connection = self._storage.connect(validated)
            try:
                self._initialize(connection)
                rows = connection.execute(
                    """
                    SELECT sequence, payload, event_hash FROM audit_events
                    WHERE project = ? AND profile = ? AND chat = ?
                    ORDER BY sequence DESC LIMIT ?
                    """,
                    _scope_values(validated) + (limit,),
                ).fetchall()
            finally:
                connection.close()
        except (StorageUnavailableError, sqlite3.Error):
            raise AuditStorageError("audit_storage_unavailable") from None
        output: list[Mapping[str, Any]] = []
        for row in rows:
            try:
                payload = copy_plain_json(json.loads(row["payload"]), "stored audit event")
            except (json.JSONDecodeError, TypeError, ValueError):
                raise AuditStorageError("audit_storage_unavailable") from None
            payload["integrity_chain_hash"] = row["event_hash"]
            output.append(_freeze_json(payload))
        return tuple(output)

    def verify_chain(self, scope: Scope) -> AuditVerifyResult:
        try:
            validated = validate_scope(scope)
            connection = self._storage.connect(validated)
            try:
                self._initialize(connection)
                head = self._read_head(connection, validated)
                rows = connection.execute(
                    """
                    SELECT project, profile, chat, sequence, payload, prev_hash, event_hash
                    FROM audit_events
                    WHERE project = ? AND profile = ? AND chat = ?
                    ORDER BY sequence
                    """,
                    _scope_values(validated),
                ).fetchall()
            finally:
                connection.close()
        except (StorageUnavailableError, sqlite3.Error, ValueError):
            return AuditVerifyResult(False, "audit_storage_unavailable", 0, 0, 0)
        if head is None:
            if rows:
                return AuditVerifyResult(False, "audit_head_mismatch", 0, 0, len(rows))
            return AuditVerifyResult(True, "audit_chain_valid", 0, 0, 0)
        base_sequence = head["base_sequence"]
        head_sequence = head["head_sequence"]
        retained_count = head["retained_count"]
        if (
            type(base_sequence) is not int
            or type(head_sequence) is not int
            or type(retained_count) is not int
            or base_sequence < 0
            or head_sequence < base_sequence
            or retained_count < 0
            or type(head["base_hash"]) is not str
            or not _HASH.fullmatch(head["base_hash"])
            or type(head["head_hash"]) is not str
            or not _HASH.fullmatch(head["head_hash"])
        ):
            return AuditVerifyResult(False, "audit_head_mismatch", 0, 0, len(rows))
        if retained_count != len(rows):
            return AuditVerifyResult(
                False,
                "audit_count_mismatch",
                base_sequence,
                head_sequence,
                len(rows),
            )
        expected_sequence = base_sequence + 1
        previous_hash = head["base_hash"]
        for row in rows:
            if row["sequence"] != expected_sequence:
                return AuditVerifyResult(
                    False, "audit_sequence_mismatch", base_sequence, head_sequence, len(rows)
                )
            if (row["project"], row["profile"], row["chat"]) != _scope_values(validated):
                return AuditVerifyResult(
                    False, "audit_scope_mismatch", base_sequence, head_sequence, len(rows)
                )
            if row["prev_hash"] != previous_hash:
                return AuditVerifyResult(
                    False, "audit_prev_hash_mismatch", base_sequence, head_sequence, len(rows)
                )
            try:
                payload = copy_plain_json(json.loads(row["payload"]), "stored audit event")
                payload_scope = payload["scope"]
                if (
                    payload["schema"] != AUDIT_SCHEMA
                    or payload["sequence"] != row["sequence"]
                    or payload_scope
                    != {
                        "project": validated.project_name,
                        "profile": validated.agent_profile,
                        "chat": validated.chat_id,
                    }
                ):
                    raise ValueError("payload binding mismatch")
                calculated = _chain_hash(payload, previous_hash)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                return AuditVerifyResult(
                    False, "audit_payload_mismatch", base_sequence, head_sequence, len(rows)
                )
            if calculated != row["event_hash"]:
                return AuditVerifyResult(
                    False, "audit_hash_mismatch", base_sequence, head_sequence, len(rows)
                )
            previous_hash = row["event_hash"]
            expected_sequence += 1
        expected_head_sequence = rows[-1]["sequence"] if rows else base_sequence
        if head_sequence != expected_head_sequence or head["head_hash"] != previous_hash:
            return AuditVerifyResult(
                False, "audit_head_mismatch", base_sequence, head_sequence, len(rows)
            )
        return AuditVerifyResult(
            True, "audit_chain_valid", base_sequence, head_sequence, retained_count
        )
