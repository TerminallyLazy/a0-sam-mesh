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
        from helpers.capabilities import CapabilityProbe, REMOVED_DIAGNOSTIC_TOOLS
        from helpers.sam_client import SamClient

        async with FakeSamSidecar(server_name="sam-node-mcp") as sidecar:
            async with SamClient(config(sidecar)) as client:
                report = await CapabilityProbe(client).probe()

        self.assertEqual(report.server_name, "sam-node-mcp")
        self.assertEqual(report.status, ProbeStatus.PARTIAL)
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
        self.assertTrue(report.call_remote_tool_invocation_enabled)

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
            tool
            for tool in report.observed_tools
            if tool.canonical_uri.endswith("/call_remote_tool")
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


if __name__ == "__main__":
    unittest.main()
