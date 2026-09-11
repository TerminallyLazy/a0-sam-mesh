"""Real framework provider merge and Flask authentication/CSRF routing."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class HostIntegrationTests(unittest.TestCase):
    def test_provider_merge_and_protected_api_routes(self):
        root = Path(__file__).resolve().parents[1]
        script = r"""
import sys, threading
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
sys.path.insert(1, '/a0')
from flask import Flask
from helpers import api, cache
from helpers.providers import ProviderManager
plugin = Path(sys.argv[1]) / 'usr/plugins/sam_mesh'
with patch('helpers.plugins.get_enabled_plugin_paths', return_value=[str(plugin / 'conf/model_providers.yaml')]):
    provider = ProviderManager().get_provider_config('chat', 'sam_mesh')
    assert provider['litellm_provider'] == 'openai'
    assert provider['kwargs']['a0_api_mode'] == 'chat'
with patch('helpers.plugins.get_enabled_plugin_paths', return_value=[]):
    assert ProviderManager().get_provider_config('chat', 'sam_mesh') is None
app = Flask('sam-security')
app.secret_key = 'local-test-session-key'
app.add_url_rule('/login', 'login_handler', lambda: 'Login')
app.add_url_rule('/', 'serve_index', lambda: 'Index')
api.register_api_route(app, threading.RLock())
client = app.test_client()
with patch('helpers.plugins.find_plugin_dir', return_value=str(plugin)), patch('helpers.login.get_credentials_hash', return_value='test-authentication'):
    for name in ('status','catalog','preflight','approve','revoke','audit','emergency_disconnect'):
        route = '/api/plugins/sam_mesh/' + name
        assert client.post(route, json={}).status_code == 302
    with client.session_transaction() as session:
        session['authentication'] = 'test-authentication'
    assert client.post('/api/plugins/sam_mesh/approve', json={}).status_code == 403
    with client.session_transaction() as session:
        session['csrf_token'] = 'test-csrf'
    response = client.post('/api/plugins/sam_mesh/approve', json={}, headers={'X-CSRF-Token':'test-csrf'})
    assert response.status_code == 200, response.data
    assert response.json['error_code'] == 'context_required', response.data
print('PROVIDER_MERGE_AND_DISABLE=pass; AUTH=7; CSRF=pass; SANITIZED_API=pass')
import asyncio, json
from types import SimpleNamespace
from dataclasses import replace
from usr.plugins.sam_mesh.tests.fakes.sam_sidecar import FakeSamSidecar, FakeResponse
from usr.plugins.sam_mesh.helpers.config import resolve_config
from usr.plugins.sam_mesh.helpers.inference import guard_native_model
from usr.plugins.sam_mesh.helpers.decisions import DecisionStore
from usr.plugins.sam_mesh.helpers.leases import LeaseStore
from usr.plugins.sam_mesh.helpers.audit import AuditStore
from models import ModelConfig, ModelType, get_chat_model
import yaml
from helpers import plugins
with patch('helpers.plugins.find_plugin_dir', return_value=str(plugin)):
    default = yaml.safe_load((plugin / 'default_config.yaml').read_text())
    assert plugins.call_plugin_hook('sam_mesh', 'save_plugin_config', settings=default) == default
    default['transport']['token'] = 'CONFIG-CREDENTIAL-SENTINEL'
    for hook in ('save_plugin_config', 'get_plugin_config'):
        try:
            plugins.call_plugin_hook('sam_mesh', hook, settings=default, default=default)
            raise AssertionError('raw credential accepted')
        except ValueError as exc:
            assert str(exc) == 'invalid_sam_config'
print('HOST_CONFIG_SAVE_AND_RESPONSE_HOOKS=pass')
class InferenceSidecar(FakeSamSidecar):
    def _response(self, method, target, headers, payload):
        if target == '/v1/chat/completions':
            assert headers.get('authorization') == 'Bearer NATIVE-TEST-CREDENTIAL'
            if getattr(self, 'error_status', None):
                return self._json(self.error_status, {'error': {'message':'fixture rejection', 'type':'fixture'}})
            if not payload.get('stream'):
                message = {'role':'assistant', 'content':'probe-ok'}
                if payload.get('tools'):
                    message = {'role':'assistant','content':None,'tool_calls':[{'id':'call-fixture','type':'function',
                        'function':{'name':'response','arguments':'{"text":"tool-ok"}'}}]}
                return self._json(200, {'id':'chatcmpl-probe','object':'chat.completion','created':1,
                    'model':'probe-model','choices':[{'index':0,'message':message,'finish_reason':'tool_calls' if payload.get('tools') else 'stop'}],
                    'usage':{'prompt_tokens':2,'completion_tokens':2,'total_tokens':4}})
            choice = {'index': 0, 'delta': {'content': 'probe-ok'}, 'finish_reason': None}
            chunk = {'id':'chatcmpl-probe', 'object':'chat.completion.chunk', 'created':1,
                     'model':'probe-model', 'choices':[choice]}
            final = {**chunk, 'choices':[{'index':0, 'delta':{}, 'finish_reason':'stop'}]}
            body = ('data: ' + json.dumps(chunk) + '\n\ndata: ' + json.dumps(final) + '\n\ndata: [DONE]\n\n').encode()
            return FakeResponse(200, content_type='text/event-stream', body=body)
        return super()._response(method, target, headers, payload)
async def check_native():
    async with InferenceSidecar() as sidecar:
        raw = yaml.safe_load((plugin / 'default_config.yaml').read_text())
        raw['transport'].update(type='http', base_url=sidecar.base_url, socket_path='')
        raw['passport']['mode'] = 'guarded_mesh'
        raw['passport']['inference']['enabled'] = True
        raw['features']['mesh_inference'] = True
        raw['passport']['limits']['calls_per_session'] = 32
        agent = SimpleNamespace(context=SimpleNamespace(id='chat', get_data=lambda _: 'project'),
                                config=SimpleNamespace(profile='profile'))
        cfg = resolve_config(agent, raw=raw)
        cfg = replace(cfg, transport=replace(cfg.transport, token='NATIVE-TEST-CREDENTIAL'))
        options = dict(db_path=Path(sys.argv[1]) / 'native.sqlite3', trusted_root=sys.argv[1])
        stores = DecisionStore(**options), LeaseStore(**options), AuditStore(**options)
        mc = ModelConfig(type=ModelType.CHAT, provider='sam_mesh', name='probe-model', api_base=sidecar.base_url + '/v1')
        with patch('models.get_provider_config', return_value=provider), patch('models.get_api_key', return_value='NA'):
            model = get_chat_model('sam_mesh', 'probe-model', model_config=mc, **mc.build_kwargs())
        with patch('usr.plugins.sam_mesh.helpers.config.resolve_config', return_value=cfg), patch(
                'usr.plugins.sam_mesh.helpers.tool_runtime.scoped_stores', return_value=stores):
            guarded = guard_native_model(agent, model)
            async def receive(delta, total):
                return None
            text, _ = await guarded.unified_call(user_message='public probe', response_callback=receive)
            assert text == 'probe-ok', repr(text)
            text, _ = await guarded.unified_call(user_message='nonstream probe')
            assert text == 'probe-ok'
            tools = [{'type':'function','function':{'name':'response','parameters':{'type':'object','properties':{'text':{'type':'string'}}}}}]
            turn = await guarded.unified_turn(user_message='tool probe', tools=tools)
            assert turn.function_calls and turn.function_calls[0].name == 'response', 'tool call lost'
            for status, expected in ((401,'auth_required'),(403,'auth_rejected'),(404,'model_not_found'),
                                     (413,'context_too_large'),(429,'rate_limited'),(503,'provider_exhausted')):
                sidecar.error_status = status
                before = len(sidecar.received)
                try:
                    await guarded.unified_call(user_message='error probe')
                    raise AssertionError('expected mapped failure')
                except Exception as exc:
                    assert str(exc) == expected, (status, str(exc))
                assert len(sidecar.received) == before + 1, 'unexpected retry'
            sidecar.error_status = None
            stores[0].revoke_scope(cfg.scope)
            try:
                await guarded.unified_call(user_message='must never leave')
                raise AssertionError('stop bypass')
            except Exception as exc:
                assert str(exc) == 'emergency_disconnected', type(exc).__name__
    print('NATIVE_STREAM_NONSTREAM_TOOL_CALL=pass; ERRORS=6; EXTRA_RETRIES=0; NATIVE_OFFLINE_STOP=pass')
asyncio.run(check_native())
"""
        with tempfile.TemporaryDirectory() as directory:
            plugins = Path(directory) / "usr/plugins"
            plugins.mkdir(parents=True)
            (plugins / "sam_mesh").symlink_to(root, target_is_directory=True)
            result = subprocess.run(
                ["/opt/venv-a0/bin/python", "-c", script, directory],
                cwd="/a0",
                text=True,
                capture_output=True,
                timeout=90,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("CSRF=pass", result.stdout)
        self.assertNotIn("NATIVE-TEST-CREDENTIAL", result.stdout + result.stderr)
