"""Connection bootstrap is coordinated on the verified database inode."""

import fcntl
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from helpers.domain import Scope
from helpers.storage import SQLiteStorage, StorageUnavailableError


class SQLiteBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "state.sqlite3"
        self.storage = SQLiteStorage(db_path=self.path, trusted_root=self.root)
        self.scope = Scope("project", "profile", "chat")

    def test_busy_inode_bootstrap_fails_bounded_before_sqlite_and_then_recovers(self):
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch("helpers.storage.BUSY_TIMEOUT_MS", 20):
                with self.assertRaisesRegex(StorageUnavailableError, "storage_unavailable"):
                    connection = self.storage.connect(self.scope)
                    connection.close()
            self.assertEqual(self.path.stat().st_size, 0)
        finally:
            os.close(descriptor)
        connection = self.storage.connect(self.scope)
        try:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        finally:
            connection.close()

    def test_actual_wal_configuration_holds_bootstrap_lock_on_pinned_inode(self):
        from helpers import storage

        execute = storage._AnchoredConnection.execute
        checks = []

        def observed(connection, sql, *args):
            if sql == "PRAGMA journal_mode = WAL":
                descriptor = os.open(self.path, os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    checks.append(True)
                finally:
                    os.close(descriptor)
            return execute(connection, sql, *args)

        with patch.object(storage._AnchoredConnection, "execute", observed):
            connection = self.storage.connect(self.scope)
            connection.close()
        self.assertEqual(checks, [True])

    def test_sqlite_failure_releases_bootstrap_and_preserves_sanitized_error(self):
        import sqlite3

        with patch(
            "helpers.storage.sqlite3.connect",
            side_effect=sqlite3.OperationalError("private debug sentinel"),
        ):
            with self.assertRaisesRegex(StorageUnavailableError, "storage_unavailable") as caught:
                self.storage.connect(self.scope)
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn("sentinel", str(caught.exception))
        descriptor = os.open(self.path, os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
        connection = self.storage.connect(self.scope)
        connection.close()

    def test_unlinked_sidecar_stat_is_refreshed_before_validation(self):
        from helpers import storage

        sidecar = self.path.with_name(self.path.name + "-shm")
        descriptor = os.open(sidecar, os.O_CREAT | os.O_RDWR, 0o600)
        sidecar.unlink()
        vanished = os.fstat(descriptor)
        os.close(descriptor)
        self.assertEqual(vanished.st_nlink, 0)
        actual_stat = storage.os.stat
        observations = []

        def raced_stat(path, *args, **kwargs):
            if path == sidecar.name:
                observations.append(path)
                if len(observations) == 1:
                    return vanished
            return actual_stat(path, *args, **kwargs)

        with patch.object(storage.os, "stat", raced_stat):
            connection = self.storage.connect(self.scope)
            connection.close()
        self.assertEqual(len(observations), 2)

    def test_unlinked_sidecar_refresh_still_rejects_unsafe_replacement(self):
        from helpers import storage

        for unsafe in ("symlink", "hardlink", "permissions"):
            with self.subTest(unsafe=unsafe):
                sidecar = self.path.with_name(self.path.name + "-shm")
                descriptor = os.open(sidecar, os.O_CREAT | os.O_RDWR, 0o600)
                sidecar.unlink()
                vanished = os.fstat(descriptor)
                os.close(descriptor)
                target = self.root / "replacement"
                target.write_bytes(b"unchanged sentinel")
                target.chmod(0o600)
                actual_stat = storage.os.stat
                observed = False

                def raced_stat(path, *args, **kwargs):
                    nonlocal observed
                    if path == sidecar.name and not observed:
                        observed = True
                        if unsafe == "symlink":
                            sidecar.symlink_to(target)
                        elif unsafe == "hardlink":
                            os.link(target, sidecar)
                        else:
                            sidecar.write_bytes(b"")
                            sidecar.chmod(0o644)
                        return vanished
                    return actual_stat(path, *args, **kwargs)

                with patch.object(storage.os, "stat", raced_stat):
                    with self.assertRaisesRegex(StorageUnavailableError, "storage_unavailable"):
                        self.storage.connect(self.scope)
                self.assertEqual(target.read_bytes(), b"unchanged sentinel")
                sidecar.unlink()
                target.unlink()
