"""Real installed namespace, wrappers, protected server approval and UDS roundtrip."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class InstalledFixTests(unittest.TestCase):
    def test_installed_describe_preflight_approval_invoke(self):
        root = Path(__file__).resolve().parents[1]
        script = r"""
import asyncio, json, sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
sys.path.insert(1, '/a0')
from helpers.tool import Tool
from agent import Agent
from helpers import extension
from helpers.modules import load_classes_from_file
from usr.plugins.sam_mesh.helpers import tool_runtime as rt
from usr.plugins.sam_mesh.helpers.config import resolve_config
from usr.plugins.sam_mesh.helpers.decisions import DecisionStore
from usr.plugins.sam_mesh.helpers.leases import LeaseStore
from usr.plugins.sam_mesh.helpers.audit import AuditStore
from usr.plugins.sam_mesh.helpers.gate import DelegationGate
from usr.plugins.sam_mesh.helpers.sam_client import SamClient
from usr.plugins.sam_mesh.helpers.remote_tools import RemoteTools
from usr.plugins.sam_mesh.tests.fakes.sam_sidecar import FakeSamSidecar
import yaml

class Sidecar(FakeSamSidecar):
    def _response(self, method, target, headers, payload):
        if isinstance(payload, dict) and payload.get('method') == 'tools/call':
            if payload['params']['name'] == 'describe_remote_tool':
                value = dict(peer_id='peer-finance', tool_name='mcp://finance/list-records',
                             description='Untrusted description', input_schema={
                                 'type': 'object', 'properties': {'record': {'type': 'string'}},
                                 'required': ['record'], 'additionalProperties': False})
                return self._json(200, {'jsonrpc': '2.0', 'id': payload['id'], 'result': {
                    'content': [{'type': 'text', 'text': json.dumps(value)}]}})
        return super()._response(method, target, headers, payload)

async def main():
    root = Path(sys.argv[1])
    plugin = root / 'usr/plugins/sam_mesh'
    # Keep the real Agent methods as the host's history implementation evolves.
    # Only construction/state are local: this test never starts an agent loop.
    agent = Agent.__new__(Agent)
    agent.context = SimpleNamespace(id='chat', get_data=lambda _: 'project')
    agent.config = SimpleNamespace(profile='profile')
    agent.data = {}
    # Exercise the actual host history method body: it preserves model-authored
    # arguments before native tool validation. Never claim wrapper redaction erases it.
    history = []
    agent.loop_data = SimpleNamespace(last_response='')
    agent.parse_prompt = lambda template, **kw: kw['message']
    agent.hist_add_message = lambda *args, **kw: history.append(kw['content'])
    with patch.object(extension, 'call_extensions_sync'):
        Agent.hist_add_ai_response.__wrapped__(agent, 'preexisting-sensitive-sentinel')
    assert 'preexisting-sensitive-sentinel' in str(history)
    raw = yaml.safe_load((plugin / 'default_config.yaml').read_text())
    raw['passport']['mode'] = 'guarded_mesh'
    raw['passport']['outbound'].update(allow_services=['mcp://finance/*'], deny_tools=[],
                                       remote_mutations='allow')
    raw['passport']['limits']['calls_per_session'] = 10
    raw['features']['remote_calls'] = True
    options = dict(db_path=root / 'state.sqlite3', trusted_root=root)
    stores = DecisionStore(**options), LeaseStore(**options), AuditStore(**options)
    async with Sidecar(uds_path=str(root / 'node.sock')) as server:
        raw['connection'] = 'external'
        raw['transport'].update(socket_path=server.uds_path, base_url=server.base_url)
        cfg = resolve_config(agent, raw=raw, allowed_socket_roots=(str(root),))
        async def execute(name, args):
            cls = load_classes_from_file(str(plugin / 'tools' / (name + '.py')), Tool)[0]
            tool = cls(agent, name, None, args, '', None)
            response = await tool.execute(**args)
            assert response.break_loop is False
            return json.loads(response.message)
        with patch.object(rt, 'resolve_config', return_value=cfg), patch.object(
                rt, 'scoped_stores', return_value=stores):
            identity = dict(peer_id='peer-finance', tool_name='mcp://finance/list-records')
            description = await execute('sam_describe_tool', identity)
            assert description['input_schema']['required'] == ['record']
            assert description['untrusted'] and not description['truncated']
            args = dict(**identity, arguments={'record': 'public-value'}, data_class='public')
            decision = await execute('sam_preflight_tool', args)
            assert decision['outcome'] == 'needs_approval', decision
            assert decision['risk_level'] == 'unknown'
            invoke = {'decision_id': decision['decision_id']}
            denied = await execute('sam_call_remote_tool', invoke)
            assert denied['error_code'] == 'approval_required'
            async with SamClient(cfg.transport) as client:
                gate = DelegationGate(lambda: cfg, RemoteTools(client), *stores)
                gate.approve(decision['decision_id'], approver_id='trusted-server-operator')
            result = await execute('sam_call_remote_tool', invoke)
            assert result['error_code'] is None, result
            assert (await execute('sam_call_remote_tool', invoke))['error_code'] is not None
            args['data_class'] = 'internal'
            assert (await execute('sam_preflight_tool', args))['error_code'] is not None
        calls = [r for r in server.received if isinstance(r['json'], dict)
                 and r['json'].get('method') == 'tools/call'
                 and r['json']['params']['name'] == 'call_remote_tool']
        assert len(calls) == 1
        assert stores[2].verify_chain(cfg.scope).valid
    print('INSTALLED_PUBLIC_APPROVAL_ROUNDTRIP=pass')
asyncio.run(main())
"""
        with tempfile.TemporaryDirectory() as temp:
            plugins = Path(temp) / "usr/plugins"
            plugins.mkdir(parents=True)
            (plugins / "sam_mesh").symlink_to(root, target_is_directory=True)
            result = subprocess.run(
                ["/opt/venv-a0/bin/python", "-c", script, temp],
                cwd="/a0",
                capture_output=True,
                text=True,
                timeout=45,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("INSTALLED_PUBLIC_APPROVAL_ROUNDTRIP=pass", result.stdout)
