"""Operator key provisioning preserves identity and rejects unsafe reuse."""

import importlib.util
import tempfile
import unittest
from pathlib import Path


class EmbassyProvisionTests(unittest.TestCase):
    def module(self):
        spec = importlib.util.spec_from_file_location(
            "prepare_embassy", Path(__file__).resolve().parents[1] / "scripts/prepare-embassy.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def provision(self, root):
        return self.module().provision(root / "private", root / "public", root / "socket")

    def test_repeat_preserves_identity_and_only_exports_public_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.provision(root)
            private = (root / "private/private.key").read_bytes()
            public = (root / "public/public.key").read_bytes()
            self.assertNotEqual(private, public)
            self.provision(root)
            self.assertEqual((root / "private/private.key").read_bytes(), private)
            self.assertEqual((root / "public/public.key").read_bytes(), public)
            self.assertEqual(sorted(p.name for p in (root / "public").iterdir()), ["public.key"])

    def test_unsafe_key_mode_and_changed_public_key_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.provision(root)
            key = root / "private/private.key"
            key.chmod(0o644)
            with self.assertRaises(ValueError):
                self.provision(root)
            key.chmod(0o600)
            (root / "public/public.key").write_bytes(b"not-the-public-key")
            with self.assertRaises(ValueError):
                self.provision(root)

    def test_all_nested_mount_pairs_fail_before_creating_any_key(self):
        from itertools import permutations

        for ancestor, descendant in permutations(range(3), 2):
            with (
                self.subTest(ancestor=ancestor, descendant=descendant),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                paths = [root / "private", root / "public", root / "socket"]
                paths[descendant] = paths[ancestor] / "nested"
                with self.assertRaisesRegex(ValueError, "separate_mount_directories_required"):
                    self.module().provision(*paths)
                self.assertEqual(list(root.rglob("*.key")), [])

    def test_container_bind_mount_sources_cannot_hide_nested_private_key(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [root / "private", root / "public", root / "socket"]
            for path in paths:
                path.mkdir(mode=0o700)
            mountinfo = "\n".join(
                [
                    "1 0 0:1 / / rw - overlay overlay rw",
                    f"2 1 8:1 /host/trust/private {paths[0]} rw - ext4 /dev/sda rw",
                    f"3 1 8:1 /host/trust {paths[1]} rw - ext4 /dev/sda rw",
                    f"4 1 8:1 /host/socket {paths[2]} rw - ext4 /dev/sda rw",
                ]
            )
            original_read = Path.read_text

            def read(path, *args, **kwargs):
                if str(path) == "/proc/self/mountinfo":
                    return mountinfo
                return original_read(path, *args, **kwargs)

            with patch.object(Path, "read_text", read):
                with self.assertRaisesRegex(ValueError, "separate_mount_directories_required"):
                    self.module().provision(*paths)
            self.assertEqual(list(root.rglob("*.key")), [])

    def test_linux_mount_topology_unavailable_fails_before_key_creation(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = self.module()
            with (
                patch.object(module.sys, "platform", "linux"),
                patch.object(Path, "read_text", side_effect=PermissionError("mountinfo denied")),
            ):
                with self.assertRaises(PermissionError):
                    module.provision(root / "private", root / "public", root / "socket")
            self.assertEqual(list(root.iterdir()), [])
