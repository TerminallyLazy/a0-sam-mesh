import hashlib
import os
import sqlite3
import stat
import tempfile
import threading
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from helpers.domain import DataClass, RiskLevel, RouteMode, Scope
from helpers.leases import (
    ApprovalLease,
    LeaseConsumeResult,
    LeaseRequest,
    LeaseStore,
    argument_binding_hash,
    risk_assessment_binding_hash,
)
from helpers.risk import RiskAssessment


class MutableClock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


def request(**changes):
    values = {
        "scope": Scope("project-a", "profile-a", "chat-a"),
        "peer_id": "peer-A",
        "service": "mcp://records",
        "canonical_uri": "mcp://records/update-entry",
        "schema_hash": "1" * 64,
        "risk_metadata_hash": "2" * 64,
        "passport_hash": "3" * 64,
        "route_mode": RouteMode.PINNED,
        "model": "model-A",
        "required_labels": ("region=eu", "tier=trusted"),
        "boundary_kind": "arguments",
        "boundary_hash": "4" * 64,
        "data_class": DataClass.INTERNAL,
        "risk_level": RiskLevel.MUTATION,
        "risk_assessment_hash": "5" * 64,
    }
    values.update(changes)
    return LeaseRequest(**values)


class LeaseStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.trusted_root = Path(self.temporary.name)
        self.db_path = self.trusted_root / "private" / "state.sqlite3"
        self.clock = MutableClock(datetime(2026, 9, 2, 12, 0, tzinfo=UTC))
        self.store = LeaseStore(
            db_path=self.db_path,
            trusted_root=self.trusted_root,
            clock=self.clock,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_single_use_lease_is_atomic_and_replay_is_exhausted(self):
        lease = self.store.issue(request(), ttl_seconds=60, max_uses=1)
        barrier = threading.Barrier(3)
        results = []

        def consume():
            barrier.wait()
            results.append(self.store.consume(lease.id, request()))

        threads = [threading.Thread(target=consume) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(sum(result.allowed for result in results), 1)
        self.assertEqual(
            sorted(result.reason for result in results),
            ["lease_consumed", "lease_exhausted"],
        )
        self.assertEqual(self.store.consume(lease.id, request()).reason, "lease_exhausted")

    def test_every_binding_component_mismatch_denies_before_expiry_or_exhaustion(self):
        original = request()
        changes = {
            "peer_id": "peer-B",
            "service": "mcp://other",
            "canonical_uri": "mcp://records/update-OTHER",
            "schema_hash": "a" * 64,
            "risk_metadata_hash": "b" * 64,
            "passport_hash": "c" * 64,
            "route_mode": RouteMode.AUTOMATIC,
            "model": "model-B",
            "required_labels": ("region=us",),
            "boundary_kind": "data_boundary",
            "boundary_hash": "d" * 64,
            "data_class": DataClass.CONFIDENTIAL,
            "risk_level": RiskLevel.DESTRUCTIVE,
            "risk_assessment_hash": "e" * 64,
        }
        scope_changes = (
            Scope("project-B", "profile-a", "chat-a"),
            Scope("project-a", "profile-B", "chat-a"),
            Scope("project-a", "profile-a", "chat-B"),
        )
        for changed_scope in scope_changes:
            with self.subTest(field="scope", changed_scope=changed_scope):
                lease = self.store.issue(original, ttl_seconds=60, max_uses=1)
                changed = replace(original, scope=changed_scope)
                self.assertEqual(
                    self.store.consume(lease.id, changed).reason,
                    "lease_binding_mismatch",
                )
        for field, changed_value in changes.items():
            with self.subTest(field=field):
                lease = self.store.issue(original, ttl_seconds=60, max_uses=1)
                changed = replace(original, **{field: changed_value})
                self.assertEqual(
                    self.store.consume(lease.id, changed).reason,
                    "lease_binding_mismatch",
                )

    def test_result_precedence_is_not_found_revoked_mismatch_expired_then_exhausted(self):
        original = request()
        self.assertEqual(self.store.consume("absent", original).reason, "lease_not_found")

        revoked = self.store.issue(original, ttl_seconds=60, max_uses=1)
        self.store.revoke_scope(original.scope)
        self.clock.value += timedelta(minutes=2)
        self.assertEqual(
            self.store.consume(revoked.id, replace(original, peer_id="other")).reason,
            "lease_revoked",
        )

        expiring = self.store.issue(original, ttl_seconds=10, max_uses=1)
        self.clock.value += timedelta(seconds=10)
        self.assertEqual(self.store.consume(expiring.id, original).reason, "lease_expired")

        fresh = self.store.issue(original, ttl_seconds=60, max_uses=1)
        self.assertTrue(self.store.consume(fresh.id, original).allowed)
        self.assertEqual(
            self.store.consume(fresh.id, replace(original, service="other")).reason,
            "lease_binding_mismatch",
        )

    def test_exact_scope_revocation_is_offline_idempotent_and_empty_is_not_wildcard(self):
        scopes = (
            Scope("project-a", "profile-a", "chat-a"),
            Scope("project-a", "profile-a", "chat-b"),
            Scope("project-a", "profile-b", "chat-a"),
        )
        leases = [
            self.store.issue(request(scope=scope), ttl_seconds=60, max_uses=1)
            for scope in scopes
        ]

        self.assertEqual(self.store.revoke_scope(scopes[0]), 1)
        self.assertEqual(self.store.revoke_scope(scopes[0]), 0)
        self.assertEqual(self.store.consume(leases[0].id, request(scope=scopes[0])).reason,
                         "lease_revoked")
        for lease, scope in zip(leases[1:], scopes[1:], strict=True):
            self.assertTrue(self.store.consume(lease.id, request(scope=scope)).allowed)
        with self.assertRaises(ValueError):
            self.store.revoke_scope(Scope("project-a", "profile-a", ""))

    def test_issue_validates_ttl_uses_risk_and_returns_repr_redacted_record(self):
        for ttl, uses in ((0, 1), (-1, 1), (1.5, 1), (60, 0), (60, True)):
            with self.subTest(ttl=ttl, uses=uses), self.assertRaises(ValueError):
                self.store.issue(request(), ttl_seconds=ttl, max_uses=uses)
        for level in (
            RiskLevel.MUTATION,
            RiskLevel.DESTRUCTIVE,
            RiskLevel.FINANCIAL,
            RiskLevel.CREDENTIAL,
            RiskLevel.UNKNOWN,
        ):
            with self.subTest(level=level), self.assertRaises(ValueError):
                self.store.issue(request(risk_level=level), ttl_seconds=60, max_uses=2)

        lease = self.store.issue(request(), ttl_seconds=60, max_uses=1,
                                 approver_id="user@example")
        self.assertIsInstance(lease, ApprovalLease)
        self.assertGreaterEqual(len(lease.id), 40)
        self.assertNotIn(lease.id, repr(lease))
        self.assertEqual(lease.approver_id, "user@example")
        with self.assertRaises(FrozenInstanceError):
            lease.max_uses = 2

    def test_only_digest_is_stored_and_private_wal_storage_is_used(self):
        raw_id = self.store.issue(request(), ttl_seconds=60, max_uses=1).id
        digest = hashlib.sha256(raw_id.encode()).hexdigest()
        connection = sqlite3.connect(self.db_path)
        try:
            columns = [row[1] for row in connection.execute("PRAGMA table_info(leases)")]
            row = connection.execute("SELECT lease_digest FROM leases").fetchone()
            journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            connection.close()

        self.assertNotIn("lease_id", columns)
        self.assertEqual(row[0], digest)
        self.assertEqual(journal.lower(), "wal")
        self.assertEqual(stat.S_IMODE(self.db_path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.db_path.stat().st_mode), 0o600)
        for path in (self.db_path, Path(f"{self.db_path}-wal")):
            if path.exists():
                self.assertNotIn(raw_id.encode(), path.read_bytes())

    def test_lazy_asset_resolution_passes_exact_trusted_scope(self):
        expected = Path(self.temporary.name) / "resolved" / "state.sqlite3"
        with patch(
            "helpers.storage._determine_plugin_asset_path",
            return_value=str(expected),
        ) as fn:
            store = LeaseStore(trusted_root=self.trusted_root, clock=self.clock)
            store.issue(request(), ttl_seconds=60, max_uses=1)
        fn.assert_called_with("project-a", "profile-a")

    def test_symlink_and_non_regular_database_paths_fail_closed(self):
        target = Path(self.temporary.name) / "target.sqlite3"
        target.write_text("not a db")
        link = Path(self.temporary.name) / "link.sqlite3"
        link.symlink_to(target)
        with self.assertRaisesRegex(Exception, "storage_unavailable"):
            LeaseStore(
                db_path=link,
                trusted_root=self.trusted_root,
                clock=self.clock,
            ).issue(
                request(), ttl_seconds=60, max_uses=1
            )

        real_parent = Path(self.temporary.name) / "real-parent"
        real_parent.mkdir()
        linked_parent = Path(self.temporary.name) / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(Exception, "storage_unavailable"):
            LeaseStore(
                db_path=linked_parent / "state.sqlite3",
                trusted_root=self.trusted_root,
                clock=self.clock,
            ).issue(request(), ttl_seconds=60, max_uses=1)

        directory = Path(self.temporary.name) / "directory.sqlite3"
        directory.mkdir()
        with self.assertRaisesRegex(Exception, "storage_unavailable"):
            LeaseStore(
                db_path=directory,
                trusted_root=self.trusted_root,
                clock=self.clock,
            ).issue(
                request(), ttl_seconds=60, max_uses=1
            )

    def test_storage_failure_denies_with_stable_sanitized_result(self):
        lease = self.store.issue(request(), ttl_seconds=60, max_uses=1)
        os.chmod(self.db_path, 0)
        self.db_path.unlink()
        self.db_path.mkdir()
        result = self.store.consume(lease.id, request())
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "lease_storage_unavailable")
        self.assertNotIn(str(self.db_path), repr(result))

    def test_canonical_binding_hashes_are_domain_separated_finite_and_order_independent(self):
        first = argument_binding_hash({"b": [2, 3], "a": 1})
        second = argument_binding_hash({"a": 1, "b": [2, 3]})
        boundary = argument_binding_hash({"a": 1, "b": [2, 3]},
                                         boundary_kind="data_boundary")
        assessment = RiskAssessment(
            RiskLevel.MUTATION,
            True,
            ("classified_mutation",),
            ("identity:tool:mutation.update",),
        )
        self.assertEqual(first, second)
        self.assertNotEqual(first, boundary)
        self.assertNotEqual(first, risk_assessment_binding_hash(assessment))
        with self.assertRaises(TypeError):
            argument_binding_hash({"bad": float("nan")})
        with self.assertRaises(TypeError):
            argument_binding_hash({1: "non-string-key"})

    def test_records_validate_exact_types_hashes_and_verbatim_strings(self):
        original = request(
            scope=Scope("Project Ω", "Profile One", "chat/segment"),
            canonical_uri="mcp://Records/Update%2FEntry",
        )
        self.assertEqual(original.scope, Scope("Project Ω", "Profile One", "chat/segment"))
        self.assertEqual(original.canonical_uri, "mcp://Records/Update%2FEntry")
        with self.assertRaises(ValueError):
            request(schema_hash="short")
        with self.assertRaises(TypeError):
            request(required_labels=["region=eu"])
        with self.assertRaises(ValueError):
            request(required_labels=(f"key={'x' * 600}",))
        with self.assertRaises(ValueError):
            request(scope=Scope("../escape", "profile", "chat"))

    def test_public_result_records_reject_inconsistent_or_unvalidated_values(self):
        with self.assertRaises(ValueError):
            LeaseConsumeResult(True, "lease_exhausted")
        with self.assertRaises(ValueError):
            LeaseConsumeResult(False, "invented_reason")
        with self.assertRaises(ValueError):
            ApprovalLease(
                id="x" * 43,
                request=request(),
                issued_at=datetime(2026, 9, 2),
                expires_at=self.clock.value,
                max_uses=1,
                uses=0,
            )
        with self.assertRaises(ValueError):
            ApprovalLease(
                id="x" * 43,
                request=request(),
                issued_at=self.clock.value,
                expires_at=self.clock.value + timedelta(seconds=1),
                max_uses=1,
                uses=0,
                schema="a0.sam.lease/wrong",
            )

    def test_consume_rejects_every_malformed_selected_row_before_precedence(self):
        mutations = (
            ("project", 7),
            ("profile", b"profile"),
            ("chat", ""),
            ("binding_hash", "bad"),
            ("issued_at_us", "bad"),
            ("issued_at", "2026-09-02T12:00:00Z"),
            ("expires_at_us", -1),
            ("expires_at", "not-a-time"),
            ("max_uses", 0),
            ("max_uses", 2),
            ("use_count", -1),
            ("use_count", 2),
            ("revoked", 2),
            ("revoked_at", "2026-09-02T12:00:01.000000Z"),
            ("approver_id", b"bad"),
        )
        for index, (column, value) in enumerate(mutations):
            with self.subTest(column=column, value=value):
                path = self.trusted_root / f"malformed-{index}" / "state.sqlite3"
                store = LeaseStore(
                    db_path=path,
                    trusted_root=self.trusted_root,
                    clock=self.clock,
                )
                lease = store.issue(request(), ttl_seconds=60, max_uses=1)
                connection = sqlite3.connect(path)
                try:
                    connection.execute("PRAGMA ignore_check_constraints = ON")
                    connection.execute(f"UPDATE leases SET {column} = ?", (value,))
                    connection.commit()
                finally:
                    connection.close()
                result = store.consume(lease.id, request())
                self.assertEqual(
                    result,
                    LeaseConsumeResult(False, "lease_storage_unavailable"),
                )

    def test_consume_rejects_timestamp_and_revocation_cross_field_corruption(self):
        cases = (
            (
                "UPDATE leases SET issued_at_us = issued_at_us + 1",
                (),
            ),
            (
                "UPDATE leases SET expires_at_us = issued_at_us",
                (),
            ),
            (
                "UPDATE leases SET revoked = 1, revoked_at = NULL",
                (),
            ),
            (
                "UPDATE leases SET revoked = 1, revoked_at = ?",
                ("2026-09-02T11:59:59.000000Z",),
            ),
        )
        for index, (statement, parameters) in enumerate(cases):
            with self.subTest(statement=statement):
                path = self.trusted_root / f"cross-{index}" / "state.sqlite3"
                store = LeaseStore(
                    db_path=path,
                    trusted_root=self.trusted_root,
                    clock=self.clock,
                )
                lease = store.issue(request(), ttl_seconds=60, max_uses=1)
                connection = sqlite3.connect(path)
                try:
                    connection.execute("PRAGMA ignore_check_constraints = ON")
                    connection.execute(statement, parameters)
                    connection.commit()
                finally:
                    connection.close()
                self.assertEqual(
                    store.consume(lease.id, request()).reason,
                    "lease_storage_unavailable",
                )

    def test_explicit_database_path_requires_trusted_root(self):
        with self.assertRaisesRegex(Exception, "storage_unavailable"):
            LeaseStore(db_path=self.db_path, clock=self.clock).issue(
                request(), ttl_seconds=60, max_uses=1
            )

    def test_every_database_ancestor_is_opened_without_following_symlinks(self):
        for depth in (0, 1):
            with self.subTest(depth=depth):
                root = self.trusted_root / f"ancestor-{depth}"
                root.mkdir()
                outside = self.trusted_root / f"outside-{depth}"
                outside.mkdir()
                if depth == 0:
                    (root / "one").symlink_to(outside, target_is_directory=True)
                else:
                    (root / "one").mkdir()
                    (root / "one" / "two").symlink_to(
                        outside,
                        target_is_directory=True,
                    )
                path = root / "one" / "two" / "state.sqlite3"
                with self.assertRaisesRegex(Exception, "storage_unavailable"):
                    LeaseStore(
                        db_path=path,
                        trusted_root=root,
                        clock=self.clock,
                    ).issue(request(), ttl_seconds=60, max_uses=1)

    def test_database_open_is_anchored_if_parent_path_is_substituted(self):
        parent = self.trusted_root / "anchored"
        path = parent / "state.sqlite3"
        detached = self.trusted_root / "detached"
        real_connect = sqlite3.connect
        swapped = False

        def substitute(database, *args, **kwargs):
            nonlocal swapped
            if not swapped:
                parent.rename(detached)
                parent.mkdir()
                swapped = True
            return real_connect(database, *args, **kwargs)

        with patch("helpers.storage.sqlite3.connect", side_effect=substitute):
            LeaseStore(
                db_path=path,
                trusted_root=self.trusted_root,
                clock=self.clock,
            ).issue(request(), ttl_seconds=60, max_uses=1)

        self.assertTrue((detached / "state.sqlite3").is_file())
        self.assertFalse((parent / "state.sqlite3").exists())

    def test_public_storage_errors_do_not_chain_raw_path_exceptions(self):
        self.db_path.mkdir(parents=True)
        with self.assertRaisesRegex(Exception, "lease_storage_unavailable") as captured:
            self.store.issue(request(), ttl_seconds=60, max_uses=1)
        self.assertIsNone(captured.exception.__cause__)


if __name__ == "__main__":
    unittest.main()
