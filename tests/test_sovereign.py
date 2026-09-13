"""An incomplete sandbox contract must never launch Agent Zero."""

import unittest
from pathlib import Path

import yaml


class SovereignTests(unittest.TestCase):
    def test_help_is_required_but_never_sufficient(self):
        from helpers.sovereign import REQUIRED_FLAGS, inspect_sam_box_help

        partial = inspect_sam_box_help("  --socket string\n  --bundle string")
        self.assertIn("--credential-issuer", partial["missing_flags"])
        complete = inspect_sam_box_help(
            "\n".join("  " + flag + " string" for flag in REQUIRED_FLAGS)
        )
        self.assertFalse(complete["supported"])
        self.assertEqual(complete["missing_flags"], [])
        self.assertIn("network_matrix_unverified", complete["blockers"])

    def test_agent_and_gateway_have_no_egress_or_node_socket(self):
        path = Path(__file__).parents[1] / "deploy/compose/docker-compose.sovereign.yml"
        compose = yaml.safe_load(path.read_text())
        agent = compose["services"]["agent-zero"]
        self.assertEqual(agent["network_mode"], "none")
        self.assertNotIn("node-socket", str(agent))
        self.assertNotIn("SAM_API_TOKEN", str(agent))
        self.assertEqual(
            compose["services"]["a0-ui-gateway"]["network_mode"], "service:a0-ui-network"
        )
        self.assertIn("NET_ADMIN", compose["services"]["a0-ui-network"]["cap_add"])
        gateway = compose["services"]["a0-ui-gateway"]
        self.assertNotIn("node-socket", str(gateway))
        self.assertNotIn("agent-socket", str(gateway))
        self.assertIn("ALL", gateway["cap_drop"])

    def test_receipt_is_bound_to_host_binaries_and_all_runtime_checks(self):
        from helpers.sovereign import REQUIRED_RUNTIME_CHECKS, validate_receipt

        receipt = {
            "schema": 1,
            "supported": True,
            "generated_at": 100,
            "kernel": "test",
            "binary_sha256": {"nano-init": "a"},
            "pack_sha256": "b",
            "checks": {name: True for name in REQUIRED_RUNTIME_CHECKS},
        }
        self.assertEqual(validate_receipt(receipt, {"nano-init": "a"}, "b", "test", now=101), [])
        self.assertIn(
            "certification_host_mismatch",
            validate_receipt(receipt, {"nano-init": "a"}, "b", "other", now=101),
        )
        receipt["checks"]["literal_ip_denied"] = False
        self.assertIn(
            "literal_ip_denied_unverified",
            validate_receipt(receipt, {"nano-init": "a"}, "b", "test", now=101),
        )

    def test_guest_probe_without_readonly_certification_fails_closed(self):
        from unittest.mock import patch

        from helpers.sovereign import guest_probe

        with patch("helpers.sovereign._readonly_mount", return_value=False):
            report = guest_probe()
        self.assertFalse(report["supported"])
        self.assertIn("trusted_guest_certification_required", report["blockers"])

    def test_source_hash_ignores_user_state_but_detects_core_changes(self):
        import tempfile

        from helpers.sovereign import source_sha256

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "agent.py").write_text("original")
            (root / "run_ui.py").write_text("original")
            (root / "usr").mkdir()
            for area in ("main", "fragments", "solutions"):
                (root / "knowledge" / area).mkdir(parents=True)
            original = source_sha256(root)
            (root / "usr/private-state").write_text("user state is not source")
            self.assertEqual(source_sha256(root), original)
            (root / "agent.py").write_text("changed")
            self.assertNotEqual(source_sha256(root), original)

    def test_source_requires_prepared_native_knowledge_directories(self):
        import tempfile

        from helpers.sovereign import source_sha256

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "agent.py").write_text("original")
            (root / "run_ui.py").write_text("original")
            with self.assertRaisesRegex(ValueError, "knowledge"):
                source_sha256(root)

    def test_complete_matrix_requires_native_message_completion(self):
        from helpers.sovereign import REQUIRED_RUNTIME_CHECKS

        self.assertIn("native_a0_message_loop", REQUIRED_RUNTIME_CHECKS)

    def test_verified_receipt_reports_certified_posture(self):
        import hashlib
        import json
        import os
        import platform
        import tempfile
        import time
        from unittest.mock import patch

        from helpers.sovereign import REQUIRED_RUNTIME_CHECKS, certified_probe, pack_sha256

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries = {}
            for name in ("sam-node", "sam-box", "nano-init"):
                (root / name).write_bytes(name.encode())
                binaries[name] = hashlib.sha256(name.encode()).hexdigest()
            receipt = root / "receipt.json"
            receipt.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "supported": True,
                        "generated_at": time.time(),
                        "kernel": platform.release(),
                        "binary_sha256": binaries,
                        "pack_sha256": pack_sha256(root),
                        "host_boot_id": "test-boot",
                        "a0_source_sha256": "test-source",
                        "image_reference": "test-image",
                        "firewall_image_reference": "test-firewall",
                        "checks": {name: True for name in REQUIRED_RUNTIME_CHECKS},
                    }
                )
            )
            receipt.chmod(0o600)
            with (
                patch("helpers.sovereign._boot_id", return_value="test-boot"),
                patch("helpers.sovereign.source_sha256", return_value="test-source"),
                patch.dict(
                    os.environ,
                    SOVEREIGN_RUNTIME_IMAGE="test-image",
                    SOVEREIGN_UI_IMAGE="test-firewall",
                ),
            ):
                self.assertEqual(certified_probe(receipt, root, root)["posture"], "certified")
                receipt.chmod(0o644)
                rejected = certified_probe(receipt, root, root)
                self.assertFalse(rejected["supported"])
                self.assertEqual(rejected["posture"], "experimental")

    def test_guest_privileges_reject_escape_capabilities_and_missing_nnp(self):
        from helpers.sovereign import guest_privileges_safe

        status = (
            "\n".join(
                f"{name}:\t0000000000001000"
                for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
            )
            + "\nNoNewPrivs:\t1\n"
        )
        self.assertTrue(guest_privileges_safe(status))
        self.assertFalse(
            guest_privileges_safe(status.replace("0000000000001000", "0000000000201000"))
        )
        self.assertFalse(guest_privileges_safe(status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")))
        self.assertFalse(guest_privileges_safe(""))
