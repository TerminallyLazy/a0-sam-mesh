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
            original = source_sha256(root)
            (root / "usr/private-state").write_text("user state is not source")
            self.assertEqual(source_sha256(root), original)
            (root / "agent.py").write_text("changed")
            self.assertNotEqual(source_sha256(root), original)
