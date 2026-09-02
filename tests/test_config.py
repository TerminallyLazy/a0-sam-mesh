import copy
import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from helpers.config import ConfigError, resolve_config
from helpers.domain import (
    CapabilityPassport,
    DataClass,
    MeshModel,
    OperatingMode,
    ProbeStatus,
    RiskLevel,
    RouteMode,
    Scope,
)


BASE_CONFIG = {
    "schema": "a0.sam.config/v1alpha1",
    "transport": {
        "type": "uds",
        "base_url": "http://127.0.0.1:8080",
        "socket_path": "/var/run/sam/node.sock",
        "token_secret_name": "",
        "token_file": "",
    },
    "passport": {
        "schema": "a0.sam.passport/v1alpha1",
        "mode": "explorer",
        "outbound": {
            "max_data_class": "public",
            "allow_services": [],
            "deny_tools": ["*"],
            "remote_mutations": "deny",
        },
        "inference": {
            "enabled": False,
            "route_mode": "automatic",
            "required_labels": [],
            "sensitive_data": "deny",
        },
        "limits": {
            "calls_per_session": 0,
            "discovery_timeout_seconds": 30,
            "timeout_seconds": 90,
            "approval_lease_minutes": 15,
        },
        "inbound": {"enabled": False, "services": []},
    },
    "features": {
        "remote_calls": False,
        "mesh_inference": False,
        "inbound_publication": False,
        "raw_mcp": False,
    },
}


def fake_agent() -> SimpleNamespace:
    context = SimpleNamespace(id="chat-123", project_name="project-a")
    return SimpleNamespace(context=context, config=SimpleNamespace(profile="sam-profile"))


def plugin_config() -> dict:
    return copy.deepcopy(BASE_CONFIG)


class ConfigValidationTests(unittest.TestCase):
    def test_config_rejects_raw_token_and_unmounted_socket(self):
        raw = plugin_config()
        raw["transport"]["token"] = "do-not-leak-this"
        with self.assertRaisesRegex(ConfigError, "raw token") as raised:
            resolve_config(fake_agent(), raw=raw)
        self.assertNotIn("do-not-leak-this", str(raised.exception))

        raw["transport"].pop("token")
        raw["transport"]["socket_path"] = "/tmp/attacker.sock"
        with self.assertRaisesRegex(ConfigError, "allowed socket roots"):
            resolve_config(
                fake_agent(), raw=raw, allowed_socket_roots=("/var/run/sam",)
            )

    def test_config_normalizes_any_of_labels(self):
        raw = plugin_config()
        raw["passport"]["inference"]["required_labels"] = [
            "region=us",
            "phi=false",
        ]
        cfg = resolve_config(fake_agent(), raw=raw)
        self.assertEqual(
            cfg.passport.inference.required_labels,
            ("region=us", "phi=false"),
        )
        self.assertEqual(cfg.passport.inference.label_semantics, "any_of")

    def test_unknown_keys_and_enum_values_fail_closed(self):
        cases = []
        top_level = plugin_config()
        top_level["surprise"] = True
        cases.append((top_level, "unknown keys.*surprise"))

        nested = plugin_config()
        nested["passport"]["limits"]["unbounded"] = True
        cases.append((nested, "unknown keys.*unbounded"))

        unknown_mode = plugin_config()
        unknown_mode["passport"]["mode"] = "helpful_mesh"
        cases.append((unknown_mode, "mode"))

        unknown_route = plugin_config()
        unknown_route["passport"]["inference"]["route_mode"] = "random"
        cases.append((unknown_route, "route_mode"))

        for raw, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ConfigError, message):
                    resolve_config(fake_agent(), raw=raw)

    def test_http_transport_rejects_ambiguous_or_non_http_urls(self):
        for url in (
            "ftp://sam.example",
            "http://user:password@sam.example",
            "http://sam.example/path#fragment",
            "http://sam.example/path?redirect=elsewhere",
            "http:///missing-host",
        ):
            raw = plugin_config()
            raw["transport"].update(
                {"type": "http", "base_url": url, "socket_path": None}
            )
            with self.subTest(url=url):
                with self.assertRaisesRegex(ConfigError, "base_url"):
                    resolve_config(fake_agent(), raw=raw)

    def test_mode_constraints_disable_contradictory_features(self):
        raw = plugin_config()
        raw["passport"]["inference"]["enabled"] = True
        raw["passport"]["inbound"]["enabled"] = True
        raw["features"] = {
            "remote_calls": True,
            "mesh_inference": True,
            "inbound_publication": True,
            "raw_mcp": True,
        }
        cfg = resolve_config(fake_agent(), raw=raw)
        self.assertEqual(
            cfg.features,
            replace(
                cfg.features,
                remote_calls=False,
                mesh_inference=False,
                inbound_publication=False,
                raw_mcp=False,
            ),
        )
        self.assertFalse(cfg.passport.inference.enabled)
        self.assertFalse(cfg.passport.inbound.enabled)

    def test_secret_reference_uses_scoped_agent_zero_apis(self):
        raw = plugin_config()
        raw["transport"]["token_secret_name"] = "sam_node_token"
        secret_manager = SimpleNamespace(
            load_secrets=lambda: {"SAM_NODE_TOKEN": "resolved-in-memory-token"}
        )
        agent = fake_agent()

        with (
            patch("helpers.config._load_plugin_config", return_value=raw) as load,
            patch(
                "helpers.config._load_secrets_manager", return_value=secret_manager
            ) as manager,
            patch(
                "helpers.config._context_project_name", return_value="project-from-a0"
            ) as project,
        ):
            cfg = resolve_config(agent)

        load.assert_called_once_with("sam_mesh", agent=agent)
        manager.assert_called_once_with(agent.context)
        project.assert_called_once_with(agent.context)
        self.assertEqual(cfg.transport.token, "resolved-in-memory-token")
        self.assertEqual(
            cfg.scope,
            Scope(
                project_name="project-from-a0",
                agent_profile="sam-profile",
                chat_id="chat-123",
            ),
        )

    def test_token_file_must_be_regular_mode_0600(self):
        raw = plugin_config()
        raw["transport"]["token_secret_name"] = ""
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "node.token"
            token_file.write_text("file-token\n", encoding="utf-8")
            raw["transport"]["token_file"] = str(token_file)

            token_file.chmod(0o644)
            with self.assertRaisesRegex(ConfigError, "mode 0600"):
                resolve_config(fake_agent(), raw=raw)

            token_file.chmod(0o600)
            cfg = resolve_config(fake_agent(), raw=raw)
            self.assertEqual(cfg.transport.token, "file-token")

    def test_token_file_is_read_from_the_validated_inode(self):
        raw = plugin_config()
        raw["transport"]["token_secret_name"] = ""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token_file = root / "node.token"
            replacement = root / "replacement.token"
            token_file.write_text("validated-token\n", encoding="utf-8")
            replacement.write_text("substituted-token\n", encoding="utf-8")
            token_file.chmod(0o600)
            replacement.chmod(0o600)
            raw["transport"]["token_file"] = str(token_file)
            original_open = os.open

            def substitute_then_open(path, flags, *args, **kwargs):
                if Path(path) == token_file:
                    token_file.unlink()
                    token_file.symlink_to(replacement)
                return original_open(path, flags, *args, **kwargs)

            with patch("helpers.config.os.open", substitute_then_open):
                with self.assertRaisesRegex(ConfigError, "changed during validation"):
                    resolve_config(fake_agent(), raw=raw)

    def test_token_sources_are_exclusive(self):
        raw = plugin_config()
        raw["transport"]["token_secret_name"] = "SAM_TOKEN"
        raw["transport"]["token_file"] = "/run/secrets/sam-token"
        with self.assertRaisesRegex(ConfigError, "one credential source"):
            resolve_config(fake_agent(), raw=raw)


class DomainContractTests(unittest.TestCase):
    def test_domain_enums_reject_unknown_values(self):
        expected = {
            OperatingMode: {
                "explorer",
                "guarded_mesh",
                "raw_mcp",
                "embassy",
                "sovereign",
            },
            DataClass: {"public", "internal", "confidential", "regulated"},
            RiskLevel: {
                "read_only",
                "network",
                "mutation",
                "destructive",
                "financial",
                "credential",
                "unknown",
            },
            RouteMode: {"automatic", "pinned"},
            ProbeStatus: {
                "verified_now",
                "cached",
                "partial",
                "unreachable",
                "schema_changed",
                "unsupported",
            },
        }
        for enum_type, values in expected.items():
            with self.subTest(enum_type=enum_type.__name__):
                self.assertEqual({member.value for member in enum_type}, values)
                with self.assertRaises(ValueError):
                    enum_type("future_value")

    def test_records_are_frozen_and_lease_scope_is_explicit(self):
        cfg = resolve_config(fake_agent(), raw=plugin_config())
        with self.assertRaises(FrozenInstanceError):
            cfg.scope.chat_id = "other-chat"
        self.assertEqual(
            (cfg.scope.project_name, cfg.scope.agent_profile, cfg.scope.chat_id),
            ("project-a", "sam-profile", "chat-123"),
        )

        model = MeshModel(
            id="research-model",
            owned_by="sam",
            peer_id="peer-1",
            service="researcher",
            labels=("region=us",),
            local_proxy_url="http://127.0.0.1:8080/sam/peer-1/inference/researcher",
            discovered_at="2026-09-01T00:00:00Z",
            discovery_source="models_and_catalog",
        )
        with self.assertRaises(FrozenInstanceError):
            model.peer_id = "peer-2"

    def test_passport_hash_is_sha256_of_canonical_json(self):
        cfg = resolve_config(fake_agent(), raw=plugin_config())
        passport = cfg.passport
        self.assertIsInstance(passport, CapabilityPassport)
        canonical = json.dumps(
            passport.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.assertEqual(passport.version_hash(), hashlib.sha256(canonical).hexdigest())
        self.assertEqual(len(passport.version_hash()), 64)


if __name__ == "__main__":
    unittest.main()
