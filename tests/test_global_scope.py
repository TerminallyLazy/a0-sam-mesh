"""Global/default scopes are exact SQL identities, never wildcards."""

import tempfile
import unittest
from pathlib import Path

from helpers.domain import Scope
from helpers.leases import LeaseStore
from tests.test_leases import request


class GlobalScopeTests(unittest.TestCase):
    def test_global_default_scope_cannot_consume_project_lease(self):
        with tempfile.TemporaryDirectory() as root:
            store = LeaseStore(db_path=Path(root) / "state.sqlite3", trusted_root=root)
            global_request = request(scope=Scope("", "", "chat"))
            project_request = request(scope=Scope("project", "profile", "chat"))
            lease = store.issue(global_request, 60, 1)
            self.assertFalse(store.consume(lease.id, project_request).allowed)
            self.assertTrue(store.consume(lease.id, global_request).allowed)
