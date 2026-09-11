"""Setup remains plan-only and reports the observed safe tool surface."""

from dataclasses import replace
from types import SimpleNamespace

from tests.test_gate import GateTests


class SetupTests(GateTests):
    async def test_native_plan_rejects_uds_and_never_exposes_credentials(self):
        from helpers.native_mcp import build_native_mcp_plan

        report = SimpleNamespace(
            enabled_tools=("get_mesh_info",),
            observed_tools=(),
            observed_disabled_tools=("call_remote_tool",),
        )
        self.assertFalse(build_native_mcp_plan(self.config, report)["available"])
        config = replace(
            self.config,
            transport=replace(
                self.config.transport,
                type="http",
                base_url="http://127.0.0.1:8080",
                token="credential-sentinel",
            ),
        )
        plan = build_native_mcp_plan(config, report)
        self.assertNotIn("credential-sentinel", str(plan))
        self.assertIn("call_remote_tool", plan["disabled_tools"])
        self.assertFalse(plan["applied"])
        self.assertFalse(plan["available"])

    async def test_diagnostics_cannot_enroll_or_install(self):
        import importlib.util
        from pathlib import Path

        path = Path(__file__).resolve().parents[1] / "execute.py"
        spec = importlib.util.spec_from_file_location("sam_diagnostic", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report = module.local_diagnostics("/nonexistent/node.sock")
        self.assertFalse(report["socket_exists"])
        self.assertFalse(report["enrollment_performed"])
