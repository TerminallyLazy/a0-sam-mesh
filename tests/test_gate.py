"""Delegation security contracts; no live mesh or enrollment."""
import asyncio
import importlib.util
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from helpers.domain import DataClass, FeatureFlags, ResolvedConfig, Scope, TransportConfig
from helpers.audit import AuditStore
from helpers.leases import LeaseStore
from tests.test_passport import _passport, _tool


class GateAvailabilityTests(unittest.TestCase):
    def test_gate_exists(self):
        self.assertIsNotNone(importlib.util.find_spec('helpers.gate'),
                             'Task 6 needs an executable DelegationGate')


class GateTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from helpers.gate import DelegationGate
        from helpers.decisions import DecisionStore
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = datetime(2026, 9, 8, tzinfo=UTC)
        opts = dict(db_path=Path(self.tmp.name) / 'state.sqlite3',
                    trusted_root=self.tmp.name, clock=lambda: self.now)
        self.store = DecisionStore(**opts)
        self.leases = LeaseStore(**opts)
        self.audit = AuditStore(**opts)
        self.config = ResolvedConfig(
            TransportConfig('uds', 'http://sam.local', '/run/sam.sock', None),
            _passport(remote_mutations='allow'), FeatureFlags(True, False, False, False),
            Scope('project', 'profile', 'chat'))
        self.tool = _tool('mcp://finance/update-record')
        self.calls = 0
        self.fail_remote = False
        self.waiter = None
        owner = self

        class Adapter:
            risk_metadata_verified = True
            async def describe(self, peer, uri):
                return owner.tool
            async def call(self, descriptor, arguments, labels):
                from helpers.sam_client import ToolResult
                from helpers.mcp_transport import SamCallAmbiguous
                owner.calls += 1
                if owner.waiter:
                    await owner.waiter.wait()
                if owner.fail_remote:
                    raise SamCallAmbiguous('unsafe secret exception', dispatched=True)
                return ToolResult(({'type': 'text', 'text': 'ok'},), {}, False)

        self.adapter = Adapter()
        self.gate = DelegationGate(lambda: self.config, self.adapter, self.store,
                                   self.leases, self.audit)

    async def preflight(self, args=None):
        return await self.gate.preflight(self.tool.peer_id, self.tool.canonical_uri,
                                         args or {'record': 'private-sentinel'},
                                         DataClass.INTERNAL)

    async def approved(self):
        decision = await self.preflight()
        self.gate.approve(decision.decision_id, approver_id='operator')
        return decision

    async def test_unapproved_denied_even_mutations_allow(self):
        decision = await self.preflight()
        self.assertEqual(decision.outcome, 'needs_approval')
        result = await self.gate.invoke(decision.decision_id)
        self.assertEqual(result.error_code, 'approval_required')
        self.assertEqual(self.calls, 0)

    async def test_ambiguous_mutation_one_call_and_no_replay(self):
        decision = await self.approved()
        self.fail_remote = True
        result = await self.gate.invoke(decision.decision_id)
        self.assertEqual(result.error_code, 'duplicate_execution_possible')
        self.assertNotIn('unsafe secret', repr(result))
        await self.gate.invoke(decision.decision_id)
        self.assertEqual(self.calls, 1)

    async def test_current_scope_passport_feature_route_labels_changes_deny(self):
        for change in (
            lambda c: replace(c, scope=replace(c.scope, chat_id='other')),
            lambda c: replace(c, scope=replace(c.scope, agent_profile='other')),
            lambda c: replace(c, scope=replace(c.scope, project_name='other')),
            lambda c: replace(c, features=replace(c.features, remote_calls=False)),
            lambda c: replace(c, transport=replace(c.transport, base_url='http://other')),
            lambda c: replace(c, passport=replace(c.passport, inference=replace(
                c.passport.inference, required_labels=('region=eu',)))),
        ):
            with self.subTest(change=change):
                old = self.config
                decision = await self.approved()
                self.config = change(old)
                result = await self.gate.invoke(decision.decision_id)
                self.assertIsNotNone(result.error_code)
                self.config = old
        self.assertEqual(self.calls, 0)

    async def test_schema_annotations_peer_service_and_arguments_invalidate(self):
        original = self.tool
        for tool in (
            _tool(original.canonical_uri, {'type': 'object', 'properties': {'x': {}}}),
            replace(original, annotations={'destructiveHint': True}),
            replace(original, peer_id='other'), replace(original, service='mcp://other'),
            replace(original, labels=('region=eu',)),
        ):
            decision = await self.approved()
            self.tool = tool
            self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)
            self.tool = original
        decision = await self.approved()
        payload = self.store.load(self.config.scope, decision.decision_id)
        payload['arguments'] = {'amount': 10}
        self.store.update(self.config.scope, decision.decision_id, payload)
        self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)
        self.assertEqual(self.calls, 0)

    async def test_exact_five_minute_expiry(self):
        decision = await self.approved()
        self.now += timedelta(seconds=300)
        self.assertEqual((await self.gate.invoke(decision.decision_id)).error_code,
                         'approval_expired')
        self.assertEqual(self.calls, 0)

    async def test_concurrency_quota_and_emergency(self):
        self.config = replace(self.config, passport=replace(self.config.passport,
            limits=replace(self.config.passport.limits, calls_per_session=1)))
        first, second = await self.approved(), await self.approved()
        results = await asyncio.gather(self.gate.invoke(first.decision_id),
                                       self.gate.invoke(first.decision_id))
        self.assertEqual(sum(r.error_code is None for r in results), 1)
        self.assertEqual((await self.gate.invoke(second.decision_id)).error_code,
                         'session_quota_exceeded')
        self.gate.emergency_disconnect()
        self.assertEqual((await self.gate.invoke(second.decision_id)).error_code,
                         'emergency_disconnected')
        self.assertEqual(self.calls, 1)

    async def test_cancel_consumes_without_restoration(self):
        decision = await self.approved()
        self.waiter = asyncio.Event()
        task = asyncio.create_task(self.gate.invoke(decision.decision_id))
        while not self.calls:
            await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)
        self.assertEqual(self.calls, 1)

    async def test_tcp_and_missing_metadata_fail_closed(self):
        self.config = replace(self.config, transport=replace(self.config.transport, type='http'))
        self.assertEqual((await self.preflight()).outcome, 'deny')
        self.config = replace(self.config, transport=replace(self.config.transport, type='uds'))
        self.adapter.risk_metadata_verified = False
        self.assertEqual((await self.preflight()).outcome, 'deny')
        self.assertEqual(self.calls, 0)

    async def test_audit_failure_before_dispatch_denies(self):
        decision = await self.approved()
        from unittest.mock import patch
        with patch.object(self.audit, 'append', side_effect=RuntimeError('secret')):
            result = await self.gate.invoke(decision.decision_id)
        self.assertEqual(result.error_code, 'audit_storage_unavailable')
        self.assertEqual(self.calls, 0)

    async def test_persistence_no_plain_arguments_or_bearer(self):
        decision = await self.approved()
        payload = self.store.load(self.config.scope, decision.decision_id)
        lease = payload['lease_id']
        for path in Path(self.tmp.name).glob('*'):
            if path.is_file():
                data = path.read_bytes()
                self.assertNotIn(b'private-sentinel', data)
                self.assertNotIn(lease.encode(), data)
        self.assertNotIn(lease, repr(decision))
        self.assertNotIn('private-sentinel', repr(decision))


class AdapterContracts(unittest.IsolatedAsyncioTestCase):
    async def test_source_pinned_describe_and_call_wire(self):
        from helpers.remote_tools import RemoteTools
        from helpers.sam_client import SamClient
        from tests.fakes.sam_sidecar import FakeSamSidecar
        class Sidecar(FakeSamSidecar):
            def _response(self, method, target, headers, payload):
                if isinstance(payload, dict) and payload.get('method') == 'tools/call':
                    params = payload['params']
                    if params['name'] == 'describe_remote_tool':
                        description = {'peer_id': 'peer-finance',
                                       'tool_name': 'mcp://finance/update-record',
                                       'description': 'untrusted',
                                       'input_schema': {'type': 'object'}}
                        return self._json(200, {'jsonrpc': '2.0', 'id': payload['id'],
                            'result': {'content': [{'type': 'text',
                                                   'text': json.dumps(description)}]}})
                return super()._response(method, target, headers, payload)
        with tempfile.TemporaryDirectory() as root:
            async with Sidecar(uds_path=root + '/node.sock') as server:
                cfg = TransportConfig('uds', server.base_url, server.uds_path, None)
                async with SamClient(cfg) as client:
                    adapter = RemoteTools(client)
                    descriptor = await adapter.describe('peer-finance',
                                                        'mcp://finance/update-record')
                    self.assertEqual(descriptor.canonical_uri, 'mcp://finance/update-record')
                    self.assertFalse(adapter.risk_metadata_verified,
                                     'Current SAM drops annotations; do not invent assurance')
                    await adapter.call(descriptor, {'record': 'x'}, 'region=us,phi=false')
                    call = server.received[-1]['json']['params']
                    self.assertEqual(call['name'], 'call_remote_tool')
                    self.assertEqual(call['arguments']['arguments'], {'record': 'x'})
                    self.assertEqual(call['arguments']['required_labels'], 'region=us,phi=false')

    async def test_uds_revalidated_at_connect_after_construction(self):
        import os
        from helpers.sam_client import SamClient
        from tests.fakes.sam_sidecar import FakeSamSidecar
        with tempfile.TemporaryDirectory() as root:
            async with FakeSamSidecar(uds_path=root + '/node.sock') as server:
                cfg = TransportConfig('uds', server.base_url, server.uds_path, None)
                async with SamClient(cfg) as client:
                    os.chmod(server.uds_path, 0o666)
                    with self.assertRaises(Exception):
                        await client.health()
                    self.assertEqual(server.received, [])

    async def test_adapter_denies_tcp_before_credentials_or_discovery(self):
        from helpers.remote_tools import RemoteTools
        from helpers.sam_client import SamClient
        from tests.fakes.sam_sidecar import FakeSamSidecar
        async with FakeSamSidecar() as server:
            cfg = TransportConfig('http', server.base_url, None, 'sentinel')
            async with SamClient(cfg) as client:
                with self.assertRaises(Exception):
                    await RemoteTools(client).read('get_mesh_info', {})
            self.assertEqual(server.received, [])


class GateHardeningTests(GateTests):
    async def test_invalid_remote_arguments_denied(self):
        self.tool = _tool('mcp://finance/update-record', {
            'type': 'object', 'properties': {'record': {'type': 'string'}},
            'required': ['record'], 'additionalProperties': False})
        with self.assertRaises(Exception):
            await self.preflight({'record': 7, 'extra': True})
        self.assertEqual(self.calls, 0)

    async def test_restart_and_extended_database_expiry_fail_closed(self):
        decision = await self.approved()
        with self.store.transaction(self.config.scope) as db:
            db.execute('UPDATE gate_decisions SET expires=expires+999999999')
        self.now += timedelta(seconds=301)
        self.assertEqual((await self.gate.invoke(decision.decision_id)).error_code,
                         'approval_expired')

    async def test_session_busy_does_not_consume_other_decision(self):
        first, second = await self.approved(), await self.approved()
        self.waiter = asyncio.Event()
        task = asyncio.create_task(self.gate.invoke(first.decision_id))
        while not self.calls:
            await asyncio.sleep(0)
        self.assertEqual((await self.gate.invoke(second.decision_id)).error_code,
                         'invocation_in_progress')
        self.waiter.set()
        await task
        self.assertIsNone((await self.gate.invoke(second.decision_id)).error_code)


class AdditionalAdapterContracts(unittest.IsolatedAsyncioTestCase):
    async def test_inference_discovery_ignores_only_documented_second_text_hint(self):
        from helpers.remote_tools import RemoteTools
        from helpers.sam_client import SamClient
        from tests.fakes.sam_sidecar import FakeSamSidecar
        class Sidecar(FakeSamSidecar):
            def _response(self, method, target, headers, payload):
                if isinstance(payload, dict) and payload.get('method') == 'tools/call':
                    return self._json(200, {'jsonrpc': '2.0', 'id': payload['id'], 'result': {
                        'content': [{'type': 'text', 'text': '[]'},
                                    {'type': 'text', 'text': 'untrusted invocation hint'}]}})
                return super()._response(method, target, headers, payload)
        with tempfile.TemporaryDirectory() as root:
            async with Sidecar(uds_path=root + '/node.sock') as server:
                async with SamClient(TransportConfig(
                        'uds', server.base_url, server.uds_path, None)) as client:
                    self.assertEqual(await RemoteTools(client).read(
                        'discover_remote_services', {'type': 'inference'}), [])

    async def test_remote_call_schema_checked_before_description(self):
        import copy
        from helpers.remote_tools import RemoteTools
        from helpers.sam_client import SamClient
        from tests.fakes.sam_sidecar import FakeSamSidecar, CURRENT_TOOLS
        tools = copy.deepcopy(CURRENT_TOOLS)
        next(t for t in tools if t['name'] == 'call_remote_tool')['inputSchema']['properties'][
            'arguments'] = {'type': 'string'}
        with tempfile.TemporaryDirectory() as root:
            async with FakeSamSidecar(uds_path=root + '/node.sock', tools=tools) as server:
                async with SamClient(TransportConfig(
                        'uds', server.base_url, server.uds_path, None)) as client:
                    with self.assertRaises(Exception):
                        await RemoteTools(client).describe('peer', 'mcp://service/tool')
                calls = [r for r in server.received if isinstance(r['json'], dict)
                         and r['json'].get('method') == 'tools/call']
                self.assertEqual(calls, [])


class FinalGateContracts(GateTests):
    async def test_schema_change_cannot_be_reverted_to_reuse_approval(self):
        decision = await self.approved()
        original = self.tool
        self.tool = replace(original, annotations={'destructiveHint': True})
        self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)
        self.tool = original
        self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)
        self.assertEqual(self.calls, 0)

    async def test_emergency_does_not_resolve_offline_config(self):
        await self.approved()
        def offline():
            raise ValueError('socket unavailable')
        self.gate.resolve = offline
        self.gate.emergency_disconnect()
        self.assertTrue(self.store.disabled(self.config.scope))

    async def test_process_key_loss_denies_persisted_decisions(self):
        from cryptography.fernet import Fernet
        from unittest.mock import patch
        decision = await self.approved()
        with patch('helpers.decisions._CIPHER', Fernet(Fernet.generate_key())):
            self.assertEqual((await self.gate.invoke(decision.decision_id)).error_code,
                             'decision_unavailable')
        self.assertEqual(self.calls, 0)
