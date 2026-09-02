import copy
import hashlib
import json
import os
import socket
import tempfile
import unittest
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
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
    ToolDescriptor,
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
        self.assertNotIn("resolved-in-memory-token", repr(cfg.transport))
        self.assertNotIn("resolved-in-memory-token", repr(cfg))
        self.assertEqual(
            asdict(cfg.transport)["token"],
            "resolved-in-memory-token",
            "generic dataclass serialization is not a safe redaction boundary",
        )
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

    def test_uds_existing_endpoint_must_be_a_safe_owned_unix_socket(self):
        raw = plugin_config()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            endpoint = root / "node.sock"
            raw["transport"]["socket_path"] = str(endpoint)

            endpoint.write_text("not a socket", encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "Unix socket"):
                resolve_config(fake_agent(), raw=raw, allowed_socket_roots=(directory,))
            endpoint.unlink()

            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                server.bind(str(endpoint))
                endpoint.chmod(0o666)
                with self.assertRaisesRegex(ConfigError, "safe permissions"):
                    resolve_config(fake_agent(), raw=raw, allowed_socket_roots=(directory,))

                endpoint.chmod(0o600)
                real_fstat = os.fstat

                def unowned_fstat(descriptor):
                    metadata = real_fstat(descriptor)
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_uid=12_345,
                        st_dev=metadata.st_dev,
                        st_ino=metadata.st_ino,
                    )

                with patch("helpers.config.os.fstat", unowned_fstat):
                    with self.assertRaisesRegex(ConfigError, "owned by root or"):
                        resolve_config(
                            fake_agent(), raw=raw, allowed_socket_roots=(directory,)
                        )
            finally:
                server.close()

    def test_uds_rejects_symlinked_path_components(self):
        raw = plugin_config()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / "actual"
            actual.mkdir()
            linked = root / "linked"
            linked.symlink_to(actual, target_is_directory=True)
            endpoint = actual / "node.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                server.bind(str(endpoint))
                endpoint.chmod(0o600)
                raw["transport"]["socket_path"] = str(linked / "node.sock")
                with self.assertRaisesRegex(ConfigError, "symlinked path component"):
                    resolve_config(
                        fake_agent(), raw=raw, allowed_socket_roots=(directory,)
                    )
            finally:
                server.close()

    def test_uds_rejects_parent_replaced_with_symlink_during_validation(self):
        raw = plugin_config()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mounted = root / "mounted"
            actual = root / "actual"
            mounted.mkdir()
            endpoint = mounted / "node.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                server.bind(str(endpoint))
                endpoint.chmod(0o600)
                raw["transport"]["socket_path"] = str(endpoint)
                original_open = os.open

                def substitute_parent_then_open(path, flags, *args, **kwargs):
                    if Path(path) == endpoint:
                        mounted.rename(actual)
                        mounted.symlink_to(actual, target_is_directory=True)
                    return original_open(path, flags, *args, **kwargs)

                with patch("helpers.config.os.open", substitute_parent_then_open):
                    with self.assertRaisesRegex(ConfigError, "symlinked path component"):
                        resolve_config(
                            fake_agent(), raw=raw, allowed_socket_roots=(directory,)
                        )
            finally:
                server.close()

    def test_absent_uds_endpoint_is_allowed_only_without_remote_authority(self):
        explorer = resolve_config(fake_agent(), raw=plugin_config())
        self.assertEqual(explorer.transport.socket_path, "/run/sam/node.sock")

        raw = plugin_config()
        raw["passport"]["mode"] = "guarded_mesh"
        raw["features"]["remote_calls"] = True
        with self.assertRaisesRegex(ConfigError, "absent.*remote authority"):
            resolve_config(fake_agent(), raw=raw)

    def test_http_transport_rejects_dangerous_literal_ip_classes(self):
        dangerous_hosts = (
            "0.0.0.0",
            "169.254.169.254",
            "224.0.0.1",
            "240.0.0.1",
            "[::]",
            "[fe80::1]",
            "[ff02::1]",
            "[100::1]",
        )
        for host in dangerous_hosts:
            raw = plugin_config()
            raw["transport"].update(
                {
                    "type": "http",
                    "base_url": f"http://{host}:8080",
                    "socket_path": None,
                }
            )
            with self.subTest(host=host):
                with self.assertRaisesRegex(ConfigError, "literal IP"):
                    resolve_config(fake_agent(), raw=raw)

        raw = plugin_config()
        raw["transport"].update(
            {
                "type": "http",
                "base_url": "http://127.0.0.1:8080",
                "socket_path": None,
            }
        )
        self.assertEqual(
            resolve_config(fake_agent(), raw=raw).transport.base_url,
            "http://127.0.0.1:8080",
        )
        raw["transport"]["base_url"] = "http://[::1]:8080"
        self.assertEqual(
            resolve_config(fake_agent(), raw=raw).transport.base_url,
            "http://[::1]:8080",
        )

    def test_http_non_loopback_host_requires_exact_origin_policy(self):
        raw = plugin_config()
        raw["transport"].update(
            {
                "type": "http",
                "base_url": "https://sam.example:8443/v1",
                "socket_path": None,
            }
        )
        with self.assertRaisesRegex(ConfigError, "explicit allowed origin"):
            resolve_config(fake_agent(), raw=raw)

        raw["transport"]["allowed_origins"] = ["https://other.example:8443"]
        with self.assertRaisesRegex(ConfigError, "explicit allowed origin"):
            resolve_config(fake_agent(), raw=raw)

        raw["transport"]["allowed_origins"] = ["https://sam.example:8443"]
        cfg = resolve_config(fake_agent(), raw=raw)
        self.assertEqual(cfg.transport.allowed_origins, ("https://sam.example:8443",))


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

    def test_tool_descriptor_deep_freezes_schemas_and_preserves_hash_semantics(self):
        input_schema = {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["a", "b"]},
                }
            },
            "required": ["items"],
        }
        output_schema = {
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
        }
        canonical = json.dumps(
            {
                "input_schema": input_schema,
                "output_schema": output_schema,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        expected_hash = hashlib.sha256(canonical).hexdigest()
        descriptor = ToolDescriptor(
            canonical_uri=" mcp://research/run verbatim ",
            peer_id="peer-1",
            service="research",
            description="Run research",
            input_schema=input_schema,
            output_schema=output_schema,
            labels=("region=us",),
            discovered_at="2026-09-01T00:00:00Z",
            discovery_source="sam",
            schema_hash=expected_hash,
        )

        self.assertEqual(descriptor.canonical_uri, " mcp://research/run verbatim ")
        self.assertIsInstance(descriptor.input_schema, MappingProxyType)
        self.assertIsInstance(descriptor.output_schema, MappingProxyType)
        original_hash = descriptor.schema_hash
        input_schema["properties"]["items"]["items"]["type"] = "integer"
        input_schema["properties"]["items"]["items"]["enum"].append("mutated")
        input_schema["required"].append("mutated")
        output_schema["properties"]["ok"]["type"] = "string"
        self.assertEqual(
            descriptor.input_schema["properties"]["items"]["items"]["type"],
            "string",
        )
        self.assertEqual(
            descriptor.output_schema["properties"]["ok"]["type"], "boolean"
        )
        self.assertEqual(descriptor.schema_hash, original_hash)
        with self.assertRaises(TypeError):
            descriptor.input_schema["properties"]["items"]["items"]["type"] = (
                "integer"
            )

    def test_tool_descriptor_rejects_non_json_schemas_and_hash_mismatch(self):
        fields = dict(
            canonical_uri="mcp://research/run",
            peer_id="peer-1",
            service="research",
            description="Run research",
            output_schema=None,
            labels=(),
            discovered_at="2026-09-01T00:00:00Z",
            discovery_source="sam",
            schema_hash="0" * 64,
        )
        with self.assertRaisesRegex(TypeError, "JSON"):
            ToolDescriptor(input_schema={"unsupported": {"set"}}, **fields)
        with self.assertRaisesRegex(ValueError, "schema_hash"):
            ToolDescriptor(input_schema={"type": "object"}, **fields)


if __name__ == "__main__":
    unittest.main()
