"""Exact native surface and installed framework contracts."""

import importlib.util
import unittest


class ToolAvailabilityTests(unittest.TestCase):
    def test_native_runtime_exists(self):
        self.assertIsNotNone(
            importlib.util.find_spec("helpers.native_tools"),
            "Nine tools need a real installed runtime",
        )


class NativeContractTests(unittest.TestCase):
    def test_exact_surface_and_strict_arguments(self):
        from helpers.native_tools import SCHEMAS, validate_arguments

        expected = {
            "sam_mesh_status",
            "sam_list_local_services",
            "sam_discover_services",
            "sam_find_tools",
            "sam_describe_tool",
            "sam_preflight_tool",
            "sam_call_remote_tool",
            "sam_list_models",
            "sam_route_preview",
        }
        self.assertEqual(set(SCHEMAS), expected)
        for name, schema in SCHEMAS.items():
            self.assertIs(schema["additionalProperties"], False)
            with self.assertRaises(ValueError):
                validate_arguments(name, {"confirm": True})
        for value in (
            {"decision_id": "x"},
            {"decision_id": "x" * 30, "arguments": {}},
            {"decision_id": "x" * 30, "token": "sentinel"},
            {"decision_id": 42},
        ):
            with self.assertRaises(ValueError):
                validate_arguments("sam_call_remote_tool", value)
        validate_arguments("sam_call_remote_tool", {"decision_id": "x" * 30})

    def test_prompts_match_runtime_schemas(self):
        import json
        from pathlib import Path

        from helpers.native_tools import SCHEMAS

        root = Path(__file__).resolve().parents[1]
        for name, schema in SCHEMAS.items():
            text = (root / "prompts" / f"agent.system.tool.{name}.md").read_text()
            parsed = json.loads(text.split("```json\n")[1].split("```")[0])
            self.assertEqual(parsed, schema)
            self.assertIn("untrusted", text)

    def test_output_bounds_and_redaction(self):
        from helpers.domain import DataClass
        from helpers.sam_client import ToolResult
        from helpers.tool_output import inspect_result, safe_output

        self.assertEqual(safe_output({"TOKEN": "sentinel"})["TOKEN"], "[redacted]")
        self.assertNotIn("sentinel", str(safe_output({"x": "sentinel"}, token="sentinel")))
        self.assertEqual(safe_output({"x": "x" * 20000})["error_code"], "output_too_large")
        result = ToolResult(
            ({"type": "image", "data": "secret"}, {"type": "text", "text": "private-sentinel"}),
            {},
            False,
        )
        self.assertNotIn(
            "private-sentinel", str(inspect_result(result, {}, None, DataClass.INTERNAL))
        )
        self.assertNotIn("image", str(inspect_result(result, {}, None, DataClass.PUBLIC)))


class RuntimeContracts(unittest.TestCase):
    def test_runtime_module_exists(self):
        self.assertIsNotNone(importlib.util.find_spec("helpers.tool_runtime"))


class InstalledFrameworkTests(unittest.TestCase):
    def test_real_installed_wrappers_discovery_logging_and_uds_status(self):
        import os
        import subprocess
        import tempfile
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        script = r"""
import asyncio, json, sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
sys.path.insert(1, '/a0')
from helpers.tool import Tool, Response
from helpers.modules import load_classes_from_file
from helpers import files, tool_policy
from usr.plugins.sam_mesh.helpers import tool_runtime
from usr.plugins.sam_mesh.helpers.native_tools import SCHEMAS
from usr.plugins.sam_mesh.helpers.config import resolve_config
import yaml
def plugin_config():
    path = Path(sys.argv[1]) / "usr/plugins/sam_mesh/default_config.yaml"
    return yaml.safe_load(path.read_text())
def fake_agent():
    context = SimpleNamespace(id="chat", get_data=lambda key: "project")
    return SimpleNamespace(context=context,
                           config=SimpleNamespace(profile="profile"))
from usr.plugins.sam_mesh.tests.fakes.sam_sidecar import FakeSamSidecar

async def main():
    root = Path(sys.argv[1])
    history, logs = [], []
    class Log:
        id = 'log'
        def update(self, **kwargs):
            logs.append(kwargs)
        def log(self, **kwargs):
            logs.append(kwargs)
            return self
    agent = fake_agent()
    agent.context.log = Log()
    agent.agent_name = 'Test'
    agent.hist_add_tool_result = lambda *args, **kwargs: history.append((args, kwargs))
    for name in SCHEMAS:
        path = root / 'usr/plugins/sam_mesh/tools' / (name + '.py')
        classes = load_classes_from_file(str(path), Tool)
        assert len(classes) == 1 and issubclass(classes[0], Tool)
        with patch.object(files, '_base_dir', str(root)):
            assert tool_policy._canonical_from_path(str(path), name)[0] == f'plugin:sam_mesh:{name}'
        tool = classes[0](agent, name, None, {'token': 'LOG-SENTINEL'}, '', None)
        await tool.before_execution(token='LOG-SENTINEL')
        result = await tool.execute(token='LOG-SENTINEL')
        assert isinstance(result, Response) and result.break_loop is False
        assert json.loads(result.message)['error_code'] == 'invalid_tool_arguments'
        await tool.after_execution(result)
    assert 'LOG-SENTINEL' not in str(logs) + str(history)
    async with FakeSamSidecar(uds_path=str(root / 'node.sock')) as server:
        raw = plugin_config()
        raw['transport']['socket_path'] = server.uds_path
        raw['transport']['base_url'] = server.base_url
        config = resolve_config(agent, raw=raw, allowed_socket_roots=(str(root),))
        path = root / 'usr/plugins/sam_mesh/tools/sam_mesh_status.py'
        cls = load_classes_from_file(str(path), Tool)[0]
        tool = cls(agent, 'sam_mesh_status', None, {}, '', None)
        with patch.object(tool_runtime, 'resolve_config', return_value=config):
            result = await tool.execute()
        assert json.loads(result.message)['ready'] is True
        assert server.received[-1]['path'] == '/healthz'
    print('INSTALLED_WRAPPERS=9; POLICY_IDENTITIES=9; REAL_UDS_STATUS=1; LOG_SCAN=clean')
asyncio.run(main())
"""
        with tempfile.TemporaryDirectory() as temp:
            plugins = Path(temp) / "usr/plugins"
            plugins.mkdir(parents=True)
            (plugins / "sam_mesh").symlink_to(root, target_is_directory=True)
            result = subprocess.run(
                ["/opt/venv-a0/bin/python", "-c", script, temp],
                cwd="/a0",
                text=True,
                capture_output=True,
                timeout=90,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("INSTALLED_WRAPPERS=9", result.stdout)


class RuntimeErrorTests(unittest.IsolatedAsyncioTestCase):
    async def test_native_errors_keep_taxonomy_without_exception_content(self):
        import json
        from types import SimpleNamespace
        from unittest.mock import patch

        from helpers import tool_runtime
        from helpers.mcp_transport import SamAuthRejected, SamAuthRequired, SamSchemaError

        for exception, code in (
            (SamAuthRequired, "auth_required"),
            (SamAuthRejected, "auth_rejected"),
            (SamSchemaError, "schema_changed"),
        ):
            with patch.object(tool_runtime, "dispatch", side_effect=exception("secret-sentinel")):
                result = await tool_runtime.execute_native(
                    SimpleNamespace(method=None, agent=None), "sam_mesh_status", {}
                )
            self.assertEqual(json.loads(result)["error_code"], code)
            self.assertNotIn("secret-sentinel", result)
