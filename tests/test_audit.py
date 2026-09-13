import json
import sqlite3
import tempfile
import threading
import unittest
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

from helpers.audit import (
    AuditAppendResult,
    AuditEvent,
    AuditStorageError,
    AuditStore,
    AuditVerifyResult,
)
from helpers.domain import DataClass, RiskLevel, RouteMode, Scope


def plain(value):
    if isinstance(value, MappingProxyType):
        return {key: plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [plain(item) for item in value]
    return value


class MutableClock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


def event(scope=None, details=None, sensitive_paths=()):
    return AuditEvent(
        scope=scope or Scope("project-a", "profile-a", "chat-a"),
        event_type="remote_call",
        destination="mcp://peer-secret/records/update",
        decision_id="decision-raw-123",
        lease_id="lease-raw-456",
        risk_level=RiskLevel.MUTATION,
        data_class=DataClass.INTERNAL,
        route_mode=RouteMode.PINNED,
        outcome="allowed",
        latency_ms=12,
        retry_count=0,
        error_code=None,
        details={"arguments": {"query": "safe"}} if details is None else details,
        sensitive_paths=sensitive_paths,
    )


class HostileMapping(dict):
    pass


class AuditStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.trusted_root = Path(self.temporary.name)
        self.db_path = self.trusted_root / "state" / "state.sqlite3"
        self.clock = MutableClock(datetime(2026, 9, 2, 12, 0, tzinfo=UTC))
        self.store = AuditStore(
            db_path=self.db_path,
            trusted_root=self.trusted_root,
            clock=self.clock,
        )
        self.scope = Scope("project-a", "profile-a", "chat-a")

    def tearDown(self):
        self.temporary.cleanup()

    def test_recursive_and_explicit_redaction_happens_before_persistence_and_hashing(self):
        secret = "RAW-TOKEN-DO-NOT-STORE"
        result = self.store.append(
            event(
                details={
                    "arguments": {
                        "Token": secret,
                        "nested": [{"authorization": secret, "query": "safe"}],
                        "custom": secret,
                    },
                    "cookieJar": secret,
                },
                sensitive_paths=(("details", "arguments", "custom"),),
            )
        )
        exported = self.store.list_redacted(self.scope, limit=10)

        self.assertEqual(result.sequence, 1)
        self.assertEqual(exported[0]["schema"], "a0.sam.audit/v1alpha1")
        self.assertEqual(exported[0]["details"]["arguments"]["Token"], "[REDACTED]")
        self.assertEqual(
            exported[0]["details"]["arguments"]["nested"][0]["authorization"],
            "[REDACTED]",
        )
        self.assertEqual(exported[0]["details"]["arguments"]["custom"], "[REDACTED]")
        self.assertEqual(exported[0]["details"]["cookieJar"], "[REDACTED]")
        self.assertNotIn(secret, json.dumps(plain(exported)))
        for path in (self.db_path, Path(f"{self.db_path}-wal")):
            if path.exists():
                self.assertNotIn(secret.encode(), path.read_bytes())
        self.assertTrue(self.store.verify_chain(self.scope).valid)

    def test_raw_destination_decision_and_lease_ids_are_only_digest_aliases(self):
        raw_values = (
            "mcp://peer-secret/records/update",
            "decision-raw-123",
            "lease-raw-456",
        )
        self.store.append(event())
        exported = self.store.list_redacted(self.scope, limit=1)[0]
        serialized = json.dumps(plain(exported))

        for raw in raw_values:
            self.assertNotIn(raw, serialized)
            self.assertNotIn(raw.encode(), self.db_path.read_bytes())
        self.assertRegex(exported["destination_alias"], r"^dst_[0-9a-f]{24}$")
        self.assertRegex(exported["decision_alias"], r"^dec_[0-9a-f]{24}$")
        self.assertRegex(exported["lease_alias"], r"^lea_[0-9a-f]{24}$")

    def test_canonical_chain_is_independent_of_input_mapping_insertion_order(self):
        first_result = self.store.append(event(details={"z": 3, "a": {"y": 2, "x": 1}}))
        other_path = Path(self.temporary.name) / "other" / "state.sqlite3"
        other = AuditStore(db_path=other_path, trusted_root=self.trusted_root, clock=self.clock)
        second_result = other.append(event(details={"a": {"x": 1, "y": 2}, "z": 3}))

        self.assertEqual(first_result.event_hash, second_result.event_hash)
        self.assertEqual(
            json.dumps(plain(self.store.list_redacted(self.scope, limit=1)), sort_keys=True),
            json.dumps(plain(other.list_redacted(self.scope, limit=1)), sort_keys=True),
        )

    def test_append_rejects_hostile_mutable_custom_cyclic_and_nonfinite_json(self):
        cyclic = []
        cyclic.append(cyclic)
        cases = (
            HostileMapping(value="x"),
            {1: "non-string-key"},
            {"bad": float("nan")},
            {"cycle": cyclic},
            {"custom": object()},
        )
        for details in cases:
            with self.subTest(details=type(details).__name__), self.assertRaises(TypeError):
                self.store.append(event(details=details))

    def test_public_records_are_frozen_and_list_results_are_deeply_immutable_defensive_dtos(self):
        original = {"nested": [{"query": "safe"}]}
        audit_event = event(details=original)
        self.assertNotIn("mcp://peer-secret", repr(audit_event))
        self.assertNotIn("decision-raw", repr(audit_event))
        self.assertNotIn("lease-raw", repr(audit_event))
        self.assertNotIn("safe", repr(audit_event))
        original["nested"][0]["query"] = "mutated-after-construction"
        self.store.append(audit_event)
        exported = self.store.list_redacted(self.scope, limit=1)

        self.assertIsInstance(exported, tuple)
        self.assertIsInstance(exported[0], MappingProxyType)
        self.assertEqual(exported[0]["details"]["nested"][0]["query"], "safe")
        with self.assertRaises(TypeError):
            exported[0]["outcome"] = "tampered"
        with self.assertRaises(FrozenInstanceError):
            audit_event.event_type = "tampered"

    def test_concurrent_append_has_contiguous_per_scope_sequence_and_valid_chain(self):
        barrier = threading.Barrier(17)
        results, failures = [], []

        def append(index):
            barrier.wait()
            try:
                results.append(self.store.append(event(details={"index": index})))
            except Exception as error:
                failures.append(error)

        threads = [threading.Thread(target=append, args=(index,)) for index in range(16)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual([type(error).__name__ for error in failures], [])
        self.assertEqual(sorted(result.sequence for result in results), list(range(1, 17)))
        verification = self.store.verify_chain(self.scope)
        self.assertTrue(verification.valid)
        self.assertEqual(verification.head_sequence, 16)
        self.assertEqual(verification.retained_count, 16)

    def test_scope_partitions_listing_sequence_chain_retention_and_verification(self):
        other_scope = Scope("project-a", "profile-a", "chat-b")
        self.store.append(event(details={"scope": "a"}))
        self.store.append(event(scope=other_scope, details={"scope": "b"}))

        first = self.store.list_redacted(self.scope, limit=10)
        second = self.store.list_redacted(other_scope, limit=10)
        self.assertEqual(first[0]["sequence"], 1)
        self.assertEqual(second[0]["sequence"], 1)
        self.assertEqual(first[0]["details"]["scope"], "a")
        self.assertEqual(second[0]["details"]["scope"], "b")
        self.assertTrue(self.store.verify_chain(self.scope).valid)
        self.assertTrue(self.store.verify_chain(other_scope).valid)
        with self.assertRaises(ValueError):
            self.store.list_redacted(Scope("project-a", "profile-a", ""), limit=10)

    def test_listing_is_bounded_and_deterministically_newest_first(self):
        for index in range(5):
            self.store.append(event(details={"index": index}))
        listed = self.store.list_redacted(self.scope, limit=3)
        self.assertEqual([item["sequence"] for item in listed], [5, 4, 3])
        for invalid in (0, -1, 1001, True):
            with self.subTest(limit=invalid), self.assertRaises(ValueError):
                self.store.list_redacted(self.scope, limit=invalid)

    def test_count_retention_keeps_exactly_newest_ten_thousand_and_anchor_verifies(self):
        for index in range(10_001):
            self.store.append(event(details={"index": index}))

        verification = self.store.verify_chain(self.scope)
        listed = self.store.list_redacted(self.scope, limit=1000)
        connection = sqlite3.connect(self.db_path)
        try:
            count, minimum, maximum = connection.execute(
                "SELECT COUNT(*), MIN(sequence), MAX(sequence) FROM audit_events "
                "WHERE project = ? AND profile = ? AND chat = ?",
                (self.scope.project_name, self.scope.agent_profile, self.scope.chat_id),
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual((count, minimum, maximum), (10_000, 2, 10_001))
        self.assertEqual(listed[0]["sequence"], 10_001)
        self.assertTrue(verification.valid)
        self.assertEqual(verification.base_sequence, 1)
        self.assertEqual(verification.head_sequence, 10_001)
        self.assertEqual(verification.retained_count, 10_000)

    def test_thirty_day_boundary_prunes_contiguous_oldest_prefix_and_chain_stays_valid(self):
        self.store.append(event(details={"age": "exactly-thirty-days"}))
        self.clock.value += timedelta(microseconds=1)
        self.store.append(event(details={"age": "inside-boundary"}))
        self.clock.value += timedelta(days=30) - timedelta(microseconds=1)
        self.store.append(event(details={"age": "now"}))

        listed = self.store.list_redacted(self.scope, limit=10)
        self.assertEqual([item["sequence"] for item in listed], [3, 2])
        verification = self.store.verify_chain(self.scope)
        self.assertTrue(verification.valid)
        self.assertEqual(verification.base_sequence, 1)
        self.assertEqual(verification.retained_count, 2)

    def test_verify_chain_detects_payload_hash_prev_sequence_scope_head_and_count_tampering(self):
        mutations = (
            "UPDATE audit_events SET payload = '{}' WHERE sequence = 2",
            "UPDATE audit_events SET event_hash = 'bad' WHERE sequence = 2",
            "UPDATE audit_events SET prev_hash = 'bad' WHERE sequence = 2",
            "UPDATE audit_events SET sequence = 9 WHERE sequence = 2",
            "UPDATE audit_events SET chat = 'other' WHERE sequence = 2",
            "UPDATE audit_heads SET head_hash = 'bad'",
            "UPDATE audit_heads SET retained_count = 99",
        )
        for index, statement in enumerate(mutations):
            with self.subTest(statement=statement):
                path = Path(self.temporary.name) / f"tamper-{index}" / "state.sqlite3"
                store = AuditStore(db_path=path, trusted_root=self.trusted_root, clock=self.clock)
                store.append(event(details={"index": 1}))
                store.append(event(details={"index": 2}))
                connection = sqlite3.connect(path)
                try:
                    connection.execute(statement)
                    connection.commit()
                finally:
                    connection.close()
                result = store.verify_chain(self.scope)
                self.assertFalse(result.valid)
                self.assertRegex(result.reason, r"^audit_[a-z_]+$")
                self.assertNotIn(str(path), repr(result))

    def test_storage_errors_fail_closed_without_paths_or_exception_reprs(self):
        self.store.append(event())
        self.db_path.unlink()
        self.db_path.mkdir()
        with self.assertRaisesRegex(Exception, "audit_storage_unavailable") as captured:
            self.store.append(event())
        self.assertNotIn(str(self.db_path), str(captured.exception))
        self.assertIsNone(captured.exception.__cause__)
        result = self.store.verify_chain(self.scope)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "audit_storage_unavailable")

    def test_verify_chain_sanitizes_malformed_head_counters(self):
        self.store.append(event())
        connection = sqlite3.connect(self.db_path)
        try:
            connection.execute("UPDATE audit_heads SET base_sequence = -1")
            connection.commit()
        finally:
            connection.close()
        result = self.store.verify_chain(self.scope)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "audit_head_mismatch")

    def test_audit_result_records_reject_invalid_public_values(self):
        with self.assertRaises(ValueError):
            AuditAppendResult(0, "not-a-hash", "not-a-timestamp")
        with self.assertRaises(ValueError):
            AuditVerifyResult(False, "invented_reason", 0, 0, 0)
        with self.assertRaises(ValueError):
            AuditVerifyResult(True, "audit_chain_valid", 2, 1, 0)


class AuditFixTests(unittest.TestCase):
    setUp = AuditStoreTests.setUp
    tearDown = AuditStoreTests.tearDown

    def test_listing_rejects_tampered_sensitive_payload(self):
        self.store.append(event())
        with sqlite3.connect(self.db_path) as c:
            payload = json.loads(c.execute("SELECT payload FROM audit_events").fetchone()[0])
            payload["details"]["password"] = "tampered-sensitive-value"
            c.execute("UPDATE audit_events SET payload = ?", (json.dumps(payload),))
        with self.assertRaises(AuditStorageError) as caught:
            self.store.list_redacted(self.scope, limit=1)
        self.assertEqual(str(caught.exception), "audit_storage_unavailable")

    def test_read_snapshot_survives_interleaved_append(self):
        self.store.append(event())
        read_head = self.store._read_head
        fired = False

        def interleave(c, scope):
            nonlocal fired
            head = read_head(c, scope)
            if not fired:
                fired = True
                self.store.append(event(details={"later": True}))
            return head

        with patch.object(self.store, "_read_head", side_effect=interleave):
            result = self.store.verify_chain(self.scope)
        self.assertTrue(result.valid)
        self.assertEqual(result.head_sequence, 1)

    def test_append_rejects_bad_heads_and_timestamp_columns(self):
        cases = (
            "UPDATE audit_heads SET head_sequence = 'bad'",
            "UPDATE audit_heads SET head_hash = 'bad'",
            "UPDATE audit_heads SET retained_count = 5",
            "UPDATE audit_heads SET base_sequence = 1",
            "UPDATE audit_events SET occurred_at_us = 0",
            "UPDATE audit_events SET occurred_at_us = 9000000000000000",
            "UPDATE audit_events SET occurred_at = 'bad'",
        )
        for i, sql in enumerate(cases):
            with self.subTest(sql=sql):
                path = self.trusted_root / f"bad-{i}" / "state.sqlite3"
                store = AuditStore(db_path=path, trusted_root=self.trusted_root, clock=self.clock)
                store.append(event())
                with sqlite3.connect(path) as c:
                    c.execute(sql)
                with self.assertRaises(AuditStorageError):
                    store.append(event())
                self.assertFalse(store.verify_chain(self.scope).valid)
                with self.assertRaises(AuditStorageError):
                    store.list_redacted(self.scope, limit=1)
                with sqlite3.connect(path) as c:
                    count = c.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
                    self.assertEqual(count, 1)

    def test_exact_sensitive_segments_and_strict_timestamp(self):
        details = {"a.b/~": [{"0": "hide", "keep": "yes"}], "a": {"b": "keep"}}
        self.store.append(
            event(
                details=details,
                sensitive_paths=(("details", "a.b/~", 0, "0"),),
            )
        )
        dto = self.store.list_redacted(self.scope, limit=1)[0]["details"]
        self.assertEqual(dto["a.b/~"][0]["0"], "[REDACTED]")
        self.assertEqual(dto["a"]["b"], "keep")
        with self.assertRaises((TypeError, ValueError)):
            event(sensitive_paths=("details.a.b",))
        for timestamp in ("nonsenseZ", "2026-09-02T00:00:00Z", "2026-02-30T00:00:00.000000Z"):
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                AuditAppendResult(1, "a" * 64, timestamp)


class AuditCacheTests(unittest.TestCase):
    setUp = AuditStoreTests.setUp
    tearDown = AuditStoreTests.tearDown

    def test_warm_rows_skip_hashing_but_restart_verifies(self):
        from helpers import audit

        for _ in range(8):
            self.store.append(event())
        self.store.append(event())
        with patch.object(audit, "_chain_hash", wraps=audit._chain_hash) as hashing:
            self.store.append(event())
            self.assertLessEqual(hashing.call_count, 2)
        cold = AuditStore(db_path=self.db_path, trusted_root=self.trusted_root, clock=self.clock)
        with patch.object(audit, "_chain_hash", wraps=audit._chain_hash) as hashing:
            cold.append(event())
            self.assertGreaterEqual(hashing.call_count, 11)

    def test_warm_historical_field_tampering_denies(self):
        fields = {
            "payload": "{}",
            "occurred_at_us": 0,
            "occurred_at": "bad",
            "prev_hash": "a" * 64,
            "event_hash": "b" * 64,
            "sequence": 50,
            "chat": "other",
        }
        for i, (field, value) in enumerate(fields.items()):
            with self.subTest(field=field):
                path = self.trusted_root / str(i) / "state.sqlite3"
                store = AuditStore(db_path=path, trusted_root=self.trusted_root, clock=self.clock)
                for _ in range(3):
                    store.append(event())
                with sqlite3.connect(path) as c:
                    c.execute(f"UPDATE audit_events SET {field} = ? WHERE sequence = 1", (value,))
                with self.assertRaises(AuditStorageError):
                    store.append(event())
                self.assertFalse(store.verify_chain(self.scope).valid)

    def test_rollback_does_not_publish_validation_cache(self):
        from helpers import audit

        self.store.append(event())
        with patch.object(self.store, "_prune", side_effect=sqlite3.OperationalError("test")):
            with self.assertRaises(AuditStorageError):
                self.store.append(event())
        with patch.object(audit, "_chain_hash", wraps=audit._chain_hash) as hashing:
            self.store.append(event())
            self.assertEqual(hashing.call_count, 2)

    def test_replacement_and_other_scope_are_cold(self):
        from helpers import audit

        for _ in range(3):
            self.store.append(event())
        replacement = self.trusted_root / "replacement.sqlite3"
        with sqlite3.connect(self.db_path) as source, sqlite3.connect(replacement) as target:
            source.backup(target)
        replacement.replace(self.db_path)
        with patch.object(audit, "_chain_hash", wraps=audit._chain_hash) as hashing:
            self.store.append(event())
            self.assertEqual(hashing.call_count, 4)
        other = Scope("project-a", "profile-a", "other")
        self.store.append(event(scope=other))
        self.assertEqual(self.store.verify_chain(other).retained_count, 1)

    def test_cache_bounds_and_eviction_force_full_validation(self):
        from helpers import audit

        for i in range(6):
            scope = Scope("project-a", "profile-a", f"chat-{i}")
            self.store.append(event(scope=scope))
            self.store.append(event(scope=scope))
        self.assertLessEqual(len(self.store._validated_rows), audit._CACHE_MAX_SCOPES)
        self.assertLessEqual(self.store._cache_bytes, audit._CACHE_MAX_BYTES)
        first = Scope("project-a", "profile-a", "chat-0")
        with patch.object(audit, "_chain_hash", wraps=audit._chain_hash) as hashing:
            self.store.append(event(scope=first))
            self.assertEqual(hashing.call_count, 3)
        with patch.object(audit, "_CACHE_MAX_BYTES", 1):
            self.store.append(event(scope=first))
            self.assertEqual(self.store._cache_bytes, 0)

    def test_unchanged_rows_skip_json_parsing(self):
        from helpers import audit

        for _ in range(5):
            self.store.append(event())
        with patch.object(audit.json, "loads", wraps=audit.json.loads) as parsing:
            self.store.append(event())
            self.assertEqual(parsing.call_count, 1)

    def test_warm_timestamp_tamper_cannot_prune_or_extend_retention(self):
        for i, timestamp in enumerate((0, 9000000000000000)):
            path = self.trusted_root / f"time-{i}" / "state.sqlite3"
            store = AuditStore(db_path=path, trusted_root=self.trusted_root, clock=self.clock)
            for _ in range(3):
                store.append(event())
            with sqlite3.connect(path) as c:
                c.execute(
                    "UPDATE audit_events SET occurred_at_us = ? WHERE sequence = 1", (timestamp,)
                )
            with self.assertRaises(AuditStorageError):
                store.append(event())
            with sqlite3.connect(path) as c:
                self.assertEqual(c.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 3)
            with self.assertRaises(AuditStorageError):
                store.list_redacted(self.scope, limit=1)

    def test_uncertain_connection_failure_discards_cache(self):
        from helpers import audit
        from helpers.storage import StorageUnavailableError

        for _ in range(3):
            self.store.append(event())
        with patch.object(
            self.store._storage,
            "connect",
            side_effect=StorageUnavailableError("storage_unavailable"),
        ):
            with self.assertRaises(AuditStorageError):
                self.store.append(event())
        with patch.object(audit, "_chain_hash", wraps=audit._chain_hash) as hashing:
            self.store.append(event())
            self.assertEqual(hashing.call_count, 4)

    def test_warm_capacity_append_keeps_lease_writer_responsive(self):
        import time
        from concurrent.futures import ThreadPoolExecutor

        from helpers.leases import LeaseStore
        from tests.test_leases import request

        _seed_retained_chain(self.store, self.scope, self.clock.value)
        # First append is cold; second has only the new previous tail to validate.
        self.store.append(event())
        leases = LeaseStore(db_path=self.db_path, trusted_root=self.trusted_root, clock=self.clock)
        consume_scope = Scope("project-a", "profile-a", "consume")
        consume_request = request(scope=consume_scope)
        lease = leases.issue(consume_request, 60, 1)
        leases.issue(request(scope=self.scope), 60, 1)
        locked = threading.Event()
        real_read = self.store._read_state

        def signal_writer(c, scope):
            locked.set()  # BEGIN IMMEDIATE already owns the shared writer lock.
            return real_read(c, scope)

        with ThreadPoolExecutor(max_workers=3) as executor:
            with patch.object(self.store, "_read_state", side_effect=signal_writer):
                append_job = executor.submit(self.store.append, event())
                self.assertTrue(locked.wait(5))
                started = time.perf_counter()
                consume_job = executor.submit(leases.consume, lease.id, consume_request)
                revoke_job = executor.submit(leases.revoke_scope, self.scope)
                self.assertTrue(consume_job.result(timeout=2).allowed)
                self.assertEqual(revoke_job.result(timeout=2), 1)
                elapsed = time.perf_counter() - started
                append_job.result(timeout=2)
        self.assertLess(elapsed, 1.0)
        self.assertTrue(self.store.verify_chain(self.scope).valid)


def _seed_retained_chain(store, scope, now, count=10_000):
    """Test-only valid capacity fixture; full sequential retention test stays unchanged."""
    from helpers.audit import _chain_hash
    from helpers.storage import ZERO_HASH, timestamp_text, timestamp_us

    c = store._storage.connect(scope)
    try:
        store._initialize(c)
        c.execute("BEGIN IMMEDIATE")
        values = (scope.project_name, scope.agent_profile, scope.chat_id)
        c.execute(
            "INSERT INTO audit_heads VALUES (?, ?, ?, 0, ?, 0, ?, 0)",
            values + (ZERO_HASH, ZERO_HASH),
        )
        previous = ZERO_HASH
        rows = []
        for sequence in range(1, count + 1):
            payload = store._event_payload(event(scope=scope), sequence, timestamp_text(now))
            digest = _chain_hash(payload, previous)
            rows.append(
                values
                + (
                    sequence,
                    timestamp_us(now),
                    timestamp_text(now),
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    previous,
                    digest,
                )
            )
            previous = digest
        c.executemany("INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
        c.execute(
            "UPDATE audit_heads SET head_sequence = ?, head_hash = ?, retained_count = ?",
            (count, previous, count),
        )
        c.commit()
    finally:
        c.close()


if __name__ == "__main__":
    unittest.main()
