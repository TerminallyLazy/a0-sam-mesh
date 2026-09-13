"""Operator key provisioning preserves identity and rejects unsafe reuse."""

import importlib.util
import tempfile
import unittest
from pathlib import Path


class EmbassyProvisionTests(unittest.TestCase):
    def provision(self, root):
        spec = importlib.util.spec_from_file_location(
            "prepare_embassy", Path(__file__).resolve().parents[1] / "scripts/prepare-embassy.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.provision(root / "private", root / "public", root / "socket")

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
