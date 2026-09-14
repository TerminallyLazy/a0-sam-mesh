"""Managed setup must reuse one owner, preserve identity, and fail closed."""

import asyncio
import json
import os
import re
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from helpers.managed_node import ManagedNode, _read


class ManagedNodeTests(unittest.TestCase):
    def test_bad_download_never_publishes_executables(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "bad.tar.gz"
            archive.write_bytes(b"not a trusted release")
            owner = ManagedNode(root / "managed", archive_source=archive)
            owner.ensure()
            owner.thread.join(5)
            self.assertEqual(owner.status()["error_code"], "download_checksum_failed")
            self.assertFalse(list(owner.root.rglob("sam-node")))

    def test_unsafe_runtime_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "actual").mkdir()
            (root / "managed").symlink_to(root / "actual", target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "unsafe_runtime_storage"):
                ManagedNode(root / "managed").ensure()

    def test_symlinked_ancestor_cannot_redirect_runtime_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "actual").mkdir()
            (root / "linked").symlink_to(root / "actual", target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "unsafe_runtime_storage"):
                ManagedNode(root / "linked" / "managed").ensure()
            self.assertFalse((root / "actual" / "managed").exists())

    def test_hardlinked_log_is_rejected_without_truncating_other_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "preserve"
            victim.write_text("preserve-me")
            victim.chmod(0o600)
            (root / "node.log").hardlink_to(victim)
            with self.assertRaisesRegex(RuntimeError, "unsafe_runtime_storage"):
                ManagedNode(root)._start("node", ["/bin/true"])
            self.assertEqual(victim.read_text(), "preserve-me")

    def test_duplicate_owner_does_not_start_a_second_supervisor(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = ManagedNode(Path(directory) / "managed")
            second = ManagedNode(owner.root)
            with patch.object(owner, "_binaries", side_effect=lambda: owner.stop_event.wait(5)):
                owner.ensure()
                self.assertEqual(second.ensure()["status"], "installing")
                self.assertIsNone(second.thread)
                owner.stop()

    def test_stale_ready_receipt_is_not_reported_as_running(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "status.json"
            path.write_text(json.dumps({"status": "ready", "endpoint": "http://127.0.0.1:7"}))
            path.chmod(0o600)
            self.assertEqual(ManagedNode(root).status(), {"status": "stopped"})

    @unittest.skipUnless(
        os.environ.get("SAM_MANAGED_TEST_ARCHIVE"), "requires pinned published SAM archive"
    )
    def test_published_binaries_start_authenticate_restart_and_preserve_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = ManagedNode(
                Path(directory) / "managed", archive_source=os.environ["SAM_MANAGED_TEST_ARCHIVE"]
            )
            try:
                owner.ensure()
                until = time.monotonic() + 50
                while time.monotonic() < until and owner.status()["status"] in {
                    "starting",
                    "installing",
                }:
                    time.sleep(0.2)
                self.assertEqual(owner.status()["status"], "ready", owner.status())
                transport = owner.transport()
                self.assertTrue(transport["base_url"].startswith("http://127.0.0.1:"))
                token = _read(Path(transport["token_file"]))
                self.assertNotIn(token.decode(), json.dumps(owner.status()))
                self.assertTrue(all(p.poll() is None for p in owner.children))
                from helpers.domain import TransportConfig
                from helpers.mcp_transport import SamAuthRejected
                from helpers.remote_tools import RemoteTools
                from helpers.sam_client import SamClient

                async def probe():
                    config = TransportConfig(
                        type="http",
                        base_url=transport["base_url"],
                        socket_path=None,
                        token=token.decode(),
                        allowed_origins=(),
                    )
                    async with SamClient(config) as client:
                        self.assertTrue((await client.health()).ready)
                        self.assertEqual(await client.list_models(), [])
                        adapter = RemoteTools(client)
                        self.assertEqual(
                            await adapter.read("list_local_services", {"type": "mcp"}), []
                        )
                        self.assertEqual(
                            await adapter.read(
                                "discover_remote_services", {"type": "mcp", "limit": 10}
                            ),
                            [],
                        )
                    from dataclasses import replace

                    async with SamClient(replace(config, token="wrong-test-credential")) as client:
                        self.assertTrue((await client.health()).ready)
                        with self.assertRaises(SamAuthRejected):
                            await client.list_models()

                asyncio.run(probe())
                identity = re.search(
                    r"PeerID: ([A-Za-z0-9]+)", (owner.root / "node.log").read_text()
                ).group(1)
                self.assertEqual(owner.stop()["status"], "stopped")
                owner.ensure()
                until = time.monotonic() + 50
                while time.monotonic() < until and owner.status()["status"] in {
                    "starting",
                    "installing",
                }:
                    time.sleep(0.2)
                self.assertEqual(owner.status()["status"], "ready", owner.status())
                restarted = re.search(
                    r"PeerID: ([A-Za-z0-9]+)", (owner.root / "node.log").read_text()
                ).group(1)
                self.assertEqual(restarted, identity)
                self.assertEqual(_read(Path(transport["token_file"])), token)
            finally:
                owner.stop()
