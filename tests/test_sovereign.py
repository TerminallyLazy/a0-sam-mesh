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
        self.assertTrue(compose["networks"]["ui-ingress"]["internal"])
        gateway = compose["services"]["a0-ui-gateway"]
        self.assertNotIn("node-socket", str(gateway))
        self.assertNotIn("agent-socket", str(gateway))
        self.assertIn("ALL", gateway["cap_drop"])
