from __future__ import annotations

import copy
import unittest

from helpers.domain import ProbeStatus, TransportConfig
from tests.fakes.sam_sidecar import CURRENT_TOOLS, FakeResponse, FakeSamSidecar


def config(sidecar: FakeSamSidecar) -> TransportConfig:
    return TransportConfig(
        type="http",
        base_url=sidecar.base_url,
        socket_path=None,
        token=None,
        allowed_origins=(),
    )


class CapabilityProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_current_surface_is_probed_without_recreating_removed_diagnostics(self):
        from helpers.capabilities import REMOVED_DIAGNOSTIC_TOOLS, CapabilityProbe
        from helpers.sam_client import SamClient

        async with FakeSamSidecar(server_name="sam-node-mcp") as sidecar:
            async with SamClient(config(sidecar)) as client:
                report = await CapabilityProbe(client).probe()

        self.assertEqual(report.server_name, "sam-node-mcp")
        self.assertEqual(report.status, ProbeStatus.VERIFIED_NOW)
        for name in (
            "get_mesh_info",
            "list_local_services",
            "discover_remote_services",
            "find_remote_tools",
            "describe_remote_tool",
        ):
            self.assertEqual(report.features[f"tool:{name}"].status, ProbeStatus.VERIFIED_NOW)
        for name in REMOVED_DIAGNOSTIC_TOOLS:
            self.assertEqual(report.features[f"tool:{name}"].status, ProbeStatus.UNSUPPORTED)
        self.assertNotIn("get_recent_logs", report.enabled_tools)
        self.assertEqual(len(report.observed_tools), 10)
        self.assertIn("send_message", report.observed_disabled_tools)
        self.assertIn("mesh_pubsub_broadcast", report.observed_disabled_tools)
        self.assertTrue(report.call_remote_tool_schema_compatible)
        self.assertFalse(report.call_remote_tool_invocation_enabled)

    async def test_call_remote_tool_schema_change_disables_invocation(self):
        from helpers.capabilities import CapabilityProbe
        from helpers.sam_client import SamClient

        tools = copy.deepcopy(CURRENT_TOOLS)
        call_tool = next(tool for tool in tools if tool["name"] == "call_remote_tool")
        call_tool["inputSchema"]["properties"]["arguments"]["type"] = "string"
        call_tool["inputSchema"]["properties"]["required_labels"]["type"] = "array"
        async with FakeSamSidecar(tools=tools) as sidecar:
            async with SamClient(config(sidecar)) as client:
                report = await CapabilityProbe(client).probe()

        feature = report.features["tool:call_remote_tool"]
        self.assertEqual(feature.status, ProbeStatus.SCHEMA_CHANGED)
        self.assertFalse(report.call_remote_tool_invocation_enabled)
        descriptor = next(
            tool for tool in report.observed_tools if tool.wire_name == "call_remote_tool"
        )
        self.assertEqual(
            descriptor.input_schema["properties"]["arguments"]["type"],
            "string",
        )
        self.assertEqual(len(descriptor.schema_hash), 64)

    async def test_extra_required_read_tool_property_is_schema_changed(self):
        from helpers.capabilities import CapabilityProbe
        from helpers.sam_client import SamClient

        tools = copy.deepcopy(CURRENT_TOOLS)
        descriptor = next(tool for tool in tools if tool["name"] == "get_mesh_info")
        descriptor["inputSchema"]["properties"]["unexpected"] = {"type": "string"}
        async with FakeSamSidecar(tools=tools) as sidecar:
            async with SamClient(config(sidecar)) as client:
                report = await CapabilityProbe(client).probe()

        self.assertEqual(
            report.features["tool:get_mesh_info"].status,
            ProbeStatus.SCHEMA_CHANGED,
        )
        self.assertNotIn("get_mesh_info", report.enabled_tools)

    async def test_client_collection_interfaces_return_lists(self):
        from helpers.sam_client import SamClient

        async with FakeSamSidecar() as sidecar:
            async with SamClient(config(sidecar)) as client:
                await client.initialize_mcp()
                tools = await client.list_tools()
                models = await client.list_models()

        self.assertIsInstance(tools, list)
        self.assertIsInstance(models, list)

    async def test_models_are_validated_and_normalized_without_recipient_claim(self):
        from helpers.capabilities import CapabilityProbe
        from helpers.sam_client import SamClient

        models = {
            "object": "list",
            "data": [
                {"id": "model-a", "owned_by": "peer-looking-owner"},
                {"id": "model-b"},
            ],
        }
        async with FakeSamSidecar(models=models) as sidecar:
            async with SamClient(config(sidecar)) as client:
                report = await CapabilityProbe(client).probe()

        self.assertEqual([model.id for model in report.models], ["model-a", "model-b"])
        self.assertTrue(all(model.peer_id is None for model in report.models))
        self.assertTrue(all(model.service is None for model in report.models))
        self.assertEqual(report.features["models"].status, ProbeStatus.VERIFIED_NOW)

    async def test_bad_models_make_probe_partial_not_false_support(self):
        from helpers.capabilities import CapabilityProbe
        from helpers.sam_client import SamClient

        bad_values = ({"data": "not-an-array"}, {"data": [{"id": ""}]}, [])
        for value in bad_values:
            async with FakeSamSidecar(models=value) as sidecar:
                async with SamClient(config(sidecar)) as client:
                    report = await CapabilityProbe(client).probe()
            with self.subTest(value=value):
                self.assertEqual(report.features["models"].status, ProbeStatus.SCHEMA_CHANGED)
                self.assertEqual(report.status, ProbeStatus.PARTIAL)
                self.assertEqual(report.models, ())

    async def test_readyz_200_does_not_claim_mesh_readiness(self):
        from helpers.capabilities import CapabilityProbe
        from helpers.sam_client import SamClient

        async with FakeSamSidecar(ready_payload={"ready": True}) as sidecar:
            async with SamClient(config(sidecar)) as client:
                report = await CapabilityProbe(client).probe()

        self.assertEqual(report.features["readyz"].status, ProbeStatus.VERIFIED_NOW)
        self.assertFalse(report.mesh_ready)

    async def test_missing_optional_models_endpoint_is_unsupported(self):
        from helpers.capabilities import CapabilityProbe
        from helpers.sam_client import SamClient

        async with FakeSamSidecar() as sidecar:
            sidecar.override("/v1/models", FakeResponse(404, body=b"{}"))
            async with SamClient(config(sidecar)) as client:
                report = await CapabilityProbe(client).probe()

        self.assertEqual(report.features["models"].status, ProbeStatus.UNSUPPORTED)

    async def test_status_vocabulary_mapping_is_deterministic(self):
        from helpers.capabilities import compatibility_status

        expected = {
            "supported": ProbeStatus.VERIFIED_NOW,
            "live": ProbeStatus.VERIFIED_NOW,
            "missing": ProbeStatus.UNSUPPORTED,
            "schema_mismatch": ProbeStatus.SCHEMA_CHANGED,
            "transport_failure": ProbeStatus.UNREACHABLE,
            "mixed": ProbeStatus.PARTIAL,
            "prior_reused": ProbeStatus.CACHED,
        }
        self.assertEqual(
            {name: compatibility_status(name) for name in expected},
            expected,
        )

    async def test_tools_are_unreachable_when_tools_list_transport_fails(self):
        from helpers.capabilities import CapabilityProbe
        from helpers.sam_client import SamClient

        async with FakeSamSidecar() as sidecar:
            sidecar.mcp_overrides["tools/list"] = FakeResponse(
                200,
                close_without_response=True,
            )
            async with SamClient(config(sidecar)) as client:
                report = await CapabilityProbe(client).probe()

        self.assertEqual(
            report.features["tools_list"].status,
            ProbeStatus.UNREACHABLE,
        )
        self.assertEqual(
            report.features["tool:get_mesh_info"].status,
            ProbeStatus.UNREACHABLE,
        )
        self.assertEqual(
            report.features["tool:get_recent_logs"].status,
            ProbeStatus.UNREACHABLE,
        )

    async def test_missing_call_remote_tool_is_unsupported_and_disabled(self):
        from helpers.capabilities import CapabilityProbe
        from helpers.sam_client import SamClient

        tools = [tool for tool in CURRENT_TOOLS if tool["name"] != "call_remote_tool"]
        async with FakeSamSidecar(tools=tools) as sidecar:
            async with SamClient(config(sidecar)) as client:
                report = await CapabilityProbe(client).probe()

        self.assertEqual(
            report.features["tool:call_remote_tool"].status,
            ProbeStatus.UNSUPPORTED,
        )
        self.assertFalse(report.call_remote_tool_invocation_enabled)


class CapabilityProbeFixRound1Tests(unittest.IsolatedAsyncioTestCase):
    async def test_canonical_tool_identifier_round_trips_and_bare_name_has_no_fake_uri(self):
        from helpers.sam_client import SamClient

        tools = copy.deepcopy(CURRENT_TOOLS)
        tools[0]["name"] = "mcp://service-a/send_message"
        async with FakeSamSidecar(tools=tools) as sidecar:
            async with SamClient(config(sidecar)) as client:
                observed = await client.list_tools()

        canonical = observed[0]
        bare = next(tool for tool in observed if tool.wire_name == "get_mesh_info")
        self.assertEqual(canonical.wire_name, "mcp://service-a/send_message")
        self.assertEqual(canonical.canonical_uri, "mcp://service-a/send_message")
        self.assertEqual(canonical.wire_name, canonical.canonical_uri)
        self.assertEqual(bare.wire_name, "get_mesh_info")
        self.assertIsNone(bare.canonical_uri)

    async def test_bare_tool_uri_requires_explicit_validated_service_identity(self):
        from helpers.sam_client import SamClient

        async with FakeSamSidecar() as sidecar:
            async with SamClient(
                config(sidecar),
                local_service_uri="mcp://local-node",
            ) as client:
                observed = await client.list_tools()

        tool = next(item for item in observed if item.wire_name == "get_mesh_info")
        self.assertEqual(tool.canonical_uri, "mcp://local-node/get_mesh_info")
        self.assertEqual(tool.descriptor.canonical_uri, tool.canonical_uri)

    async def test_tools_list_ingests_frozen_annotations_without_changing_schema_hash(self):
        from helpers.sam_client import SamClient

        tools = copy.deepcopy(CURRENT_TOOLS)
        tools[0]["name"] = "mcp://service-a/send_message"
        tools[0]["annotations"] = {
            "destructiveHint": True,
            "nested": {"values": ["a"]},
        }
        without_annotations = copy.deepcopy(tools)
        without_annotations[0].pop("annotations")

        async with FakeSamSidecar(tools=tools) as sidecar:
            async with SamClient(config(sidecar)) as client:
                annotated = (await client.list_tools())[0]
        async with FakeSamSidecar(tools=without_annotations) as sidecar:
            async with SamClient(config(sidecar)) as client:
                plain = (await client.list_tools())[0]

        self.assertEqual(annotated.annotations["destructiveHint"], True)
        self.assertEqual(annotated.annotations["nested"]["values"], ("a",))
        self.assertEqual(annotated.descriptor.annotations, annotated.annotations)
        self.assertEqual(annotated.schema_hash, plain.schema_hash)
        self.assertNotEqual(
            annotated.descriptor.risk_metadata_hash(),
            plain.descriptor.risk_metadata_hash(),
        )
        with self.assertRaises(TypeError):
            annotated.annotations["new"] = True

    async def test_tools_list_rejects_non_object_or_non_json_annotations(self):
        from helpers.mcp_transport import SamSchemaError
        from helpers.sam_client import SamClient

        for invalid_annotations in (
            [],
            {"priority": float("nan")},
            {"destructiveHint": "true"},
            {"readOnlyHint": 0},
            {"openWorldHint": None},
        ):
            tools = copy.deepcopy(CURRENT_TOOLS)
            tools[0]["annotations"] = invalid_annotations
            async with FakeSamSidecar(tools=tools) as sidecar:
                async with SamClient(config(sidecar)) as client:
                    with self.subTest(annotations=invalid_annotations):
                        with self.assertRaises(SamSchemaError):
                            await client.list_tools()

    async def test_mcp_tool_schema_is_deeply_immutable_source_snapshot(self):
        from helpers.sam_client import McpTool

        schema = {
            "type": "object",
            "properties": {"choice": {"enum": ["a"]}},
        }
        tool = McpTool(
            wire_name="bare",
            canonical_uri=None,
            description="test",
            input_schema=schema,
            output_schema=None,
            schema_hash="not-used-here",
            descriptor=None,
        )
        schema["properties"]["choice"]["enum"].append("b")
        self.assertEqual(
            tool.input_schema["properties"]["choice"]["enum"],
            ("a",),
        )
        with self.assertRaises(TypeError):
            tool.input_schema["properties"]["choice"]["new"] = True

    async def test_call_remote_schema_compatibility_is_not_invocation_authority(self):
        from helpers.capabilities import CapabilityProbe
        from helpers.sam_client import SamClient

        async with FakeSamSidecar() as sidecar:
            async with SamClient(config(sidecar)) as client:
                report = await CapabilityProbe(client).probe()

        self.assertTrue(report.call_remote_tool_schema_compatible)
        self.assertFalse(report.call_remote_tool_invocation_enabled)
        self.assertEqual(
            report.features["tool:call_remote_tool"].status,
            ProbeStatus.VERIFIED_NOW,
        )

    async def test_call_remote_full_schema_drift_fails_closed(self):
        from helpers.capabilities import CapabilityProbe
        from helpers.sam_client import SamClient

        mutations = (
            lambda schema: schema["properties"].update({"confirm": {"type": "boolean"}}),
            lambda schema: schema["properties"].pop("peer_id"),
            lambda schema: schema["properties"].pop("arguments"),
            lambda schema: schema["properties"].pop("required_labels"),
            lambda schema: schema.update({"required": ["peer_id"]}),
            lambda schema: schema.update({"required": ["peer_id", "tool_name", "required_labels"]}),
            lambda schema: schema["properties"]["peer_id"].update({"type": "integer"}),
            lambda schema: schema["properties"]["tool_name"].update({"type": "integer"}),
        )
        for mutate in mutations:
            tools = copy.deepcopy(CURRENT_TOOLS)
            schema = next(tool for tool in tools if tool["name"] == "call_remote_tool")[
                "inputSchema"
            ]
            mutate(schema)
            async with FakeSamSidecar(tools=tools) as sidecar:
                async with SamClient(config(sidecar)) as client:
                    report = await CapabilityProbe(client).probe()
            with self.subTest(schema=schema):
                self.assertFalse(report.call_remote_tool_schema_compatible)
                self.assertFalse(report.call_remote_tool_invocation_enabled)
                self.assertEqual(
                    report.features["tool:call_remote_tool"].status,
                    ProbeStatus.SCHEMA_CHANGED,
                )

    async def test_healthy_current_surface_aggregates_verified_now(self):
        from helpers.capabilities import CapabilityProbe
        from helpers.sam_client import SamClient

        async with FakeSamSidecar() as sidecar:
            async with SamClient(config(sidecar)) as client:
                report = await CapabilityProbe(client).probe()

        self.assertEqual(report.status, ProbeStatus.VERIFIED_NOW)
        self.assertEqual(
            report.features["tool:get_recent_logs"].status,
            ProbeStatus.UNSUPPORTED,
        )

    async def test_report_and_client_metadata_are_deeply_immutable_snapshots(self):
        from helpers.capabilities import CapabilityProbe
        from helpers.sam_client import SamClient

        ready = {"ready": True, "details": {"peers": ["peer-a"]}}
        async with FakeSamSidecar(ready_payload=ready) as sidecar:
            async with SamClient(config(sidecar)) as client:
                capabilities = await client.initialize_mcp()
                report = await CapabilityProbe(client).probe()

        ready["details"]["peers"].append("peer-b")
        self.assertEqual(report.node_metadata["readyz"]["details"]["peers"], ("peer-a",))
        with self.assertRaises(TypeError):
            report.node_metadata["readyz"]["details"]["new"] = True
        with self.assertRaises(TypeError):
            capabilities.capabilities["tools"]["listChanged"] = True

    async def test_duplicate_model_ids_are_schema_changed(self):
        from helpers.capabilities import CapabilityProbe
        from helpers.mcp_transport import SamSchemaError
        from helpers.sam_client import SamClient

        models = {"data": [{"id": "duplicate"}, {"id": "duplicate"}]}
        async with FakeSamSidecar(models=models) as sidecar:
            async with SamClient(config(sidecar)) as client:
                with self.assertRaises(SamSchemaError):
                    await client.list_models()
                report = await CapabilityProbe(client).probe()
        self.assertEqual(report.features["models"].status, ProbeStatus.SCHEMA_CHANGED)

    async def test_tools_list_dependency_preserves_initialize_failure(self):
        from helpers.capabilities import CapabilityProbe
        from helpers.sam_client import SamClient

        async with FakeSamSidecar() as sidecar:
            sidecar.mcp_overrides["initialize"] = FakeResponse(401, body=b"{}")
            async with SamClient(config(sidecar)) as client:
                report = await CapabilityProbe(client).probe()

        initialize = report.features["mcp_initialize"]
        tools_list = report.features["tools_list"]
        self.assertEqual(tools_list.status, initialize.status)
        self.assertIn(initialize.detail, tools_list.detail)
        self.assertIn("initialize", tools_list.detail)


if __name__ == "__main__":
    unittest.main()
