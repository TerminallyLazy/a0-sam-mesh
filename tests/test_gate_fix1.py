"""Fix-round authority ordering regressions."""

from dataclasses import replace
from unittest.mock import patch

from helpers.domain import DataClass
from helpers.mcp_transport import SamConnectivityError, SamSchemaError
from tests.test_gate import GateTests
from tests.test_passport import _tool


class OrderingTests(GateTests):
    async def test_required_field_change_and_revert_invalidates(self):
        original = self.tool
        decision = await self.approved()
        self.tool = _tool(
            original.canonical_uri,
            {
                "type": "object",
                "required": ["missing"],
                "properties": {"missing": {"type": "string"}},
            },
        )
        self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)
        self.tool = original
        self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)
        self.assertEqual(self.calls, 0)

    async def test_unusable_description_invalidates_but_connectivity_does_not(self):
        decision = await self.approved()
        with patch.object(self.adapter, "describe", side_effect=SamSchemaError("unusable")):
            self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)
        self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)
        second = await self.approved()
        with patch.object(self.adapter, "describe", side_effect=SamConnectivityError("offline")):
            self.assertIsNotNone((await self.gate.invoke(second.decision_id)).error_code)
        self.assertIsNone((await self.gate.invoke(second.decision_id)).error_code)


class StopTests(GateTests):
    async def test_stop_blocks_new_chat_and_other_store(self):
        from helpers.decisions import DecisionStore

        scope = replace(self.config.scope, chat_id="new-chat")
        other = DecisionStore(
            db_path=self.store.storage.path_for_scope(scope),
            trusted_root=self.tmp.name,
            clock=lambda: self.now,
        )
        self.gate.emergency_disconnect()
        self.assertTrue(other.disabled(scope))

    async def test_atomic_admission_after_stop_denied(self):
        decision = await self.approved()
        payload = self.store.load(self.config.scope, decision.decision_id)
        self.store.claim(self.config.scope, decision.decision_id, 20, payload)
        self.store.revoke_scope(self.config.scope)
        with self.assertRaises(Exception):
            self.store.admit(self.config.scope, decision.decision_id, payload)


class SchemaTests(GateTests):
    async def test_dangerous_schema_rejected_before_validator(self):
        self.tool = _tool(self.tool.canonical_uri, {"type": "object", "pattern": "(a+)+$"})
        with self.assertRaisesRegex(Exception, "unsupported_schema"):
            await self.preflight()

    async def test_unsupported_schema_change_then_revert_cannot_reuse(self):
        original = self.tool
        decision = await self.approved()
        self.tool = _tool(original.canonical_uri, {"allOf": [{"type": "object"}]})
        self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)
        self.tool = original
        self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)


class CleanupTests(GateTests):
    async def test_cleanup_failure_preserves_success_and_ambiguity(self):
        for ambiguous in (False, True):
            self.fail_remote = ambiguous
            decision = await self.approved()
            with patch.object(self.store, "finish", side_effect=RuntimeError("private")):
                result = await self.gate.invoke(decision.decision_id)
            self.assertEqual(
                result.error_code, "duplicate_execution_possible" if ambiguous else None
            )
            self.assertIn("cleanup_failed", result.degraded)
            self.store.finish(self.config.scope, decision.decision_id)

    async def test_terminal_audit_failure_preserves_success(self):
        decision = await self.approved()
        original = self.audit.append

        def append(event):
            if event.outcome == "success":
                raise RuntimeError("private")
            return original(event)

        with patch.object(self.audit, "append", side_effect=append):
            result = await self.gate.invoke(decision.decision_id)
        self.assertIsNone(result.error_code)
        self.assertIn("audit_failed", result.degraded)


class OutputTests(GateTests):
    async def test_credential_keys_collision_and_sensitive_model_payload(self):
        from helpers.native_tools import validate_arguments
        from helpers.tool_output import safe_output

        self.assertNotIn("sentinel", str(safe_output({"sentinel": "value"}, token="sentinel")))
        self.assertEqual(
            safe_output({"sentinel": 1, "[redacted]": 2}, token="sentinel")["error_code"],
            "output_redaction_uncertain",
        )
        with self.assertRaises(ValueError):
            validate_arguments(
                "sam_preflight_tool",
                {
                    "peer_id": "peer",
                    "tool_name": "mcp://service/tool",
                    "arguments": {},
                    "data_class": "internal",
                },
            )


class ProvenanceTests(GateTests):
    async def test_unavailable_observation_is_bound_and_unknown_floor(self):
        from helpers.domain import RiskLevel

        original = _tool("mcp://finance/list-records")
        unavailable = replace(original, annotation_provenance="unavailable")
        self.assertNotEqual(original.risk_metadata_hash(), unavailable.risk_metadata_hash())
        self.tool = unavailable
        assessment, policy = self.gate._policy(self.config, self.tool, {}, DataClass.PUBLIC)
        self.assertEqual(assessment.level, RiskLevel.UNKNOWN)
        self.assertTrue(assessment.requires_single_use_lease)
        self.assertEqual(policy.outcome, "needs_approval")


class DescribeTests(GateTests):
    async def test_describe_returns_bounded_schema_and_description(self):
        from helpers import tool_runtime

        with (
            patch.object(tool_runtime, "resolve_config", return_value=self.config),
            patch("helpers.tool_runtime.RemoteTools.describe", return_value=self.tool),
        ):
            value = await tool_runtime.dispatch(
                None,
                "sam_describe_tool",
                {"peer_id": self.tool.peer_id, "tool_name": self.tool.canonical_uri},
            )
        self.assertEqual(value["input_schema"]["type"], "object")
        self.assertEqual(value["description"], self.tool.description)
        self.assertTrue(value["untrusted"])


class AuditTests(GateTests):
    async def test_preflight_approval_dispatch_terminal_correlation(self):
        decision = await self.approved()
        await self.gate.invoke(decision.decision_id)
        events = self.audit.list_redacted(self.config.scope, limit=20)
        self.assertTrue(
            {"preflight", "approval", "dispatch", "success"} <= {e["outcome"] for e in events}
        )
        for e in events:
            self.assertIsInstance(e["latency_ms"], int)
            self.assertIsNotNone(e["destination_alias"])
        self.assertIsNotNone(events[0]["lease_alias"])


class ErrorAndStopOrderTests(GateTests):
    async def test_typed_auth_policy_errors_preserved(self):
        from helpers.mcp_transport import SamAuthRejected, SamPolicyDenied

        for exception, code in (
            (SamAuthRejected, "auth_rejected"),
            (SamPolicyDenied, "policy_denied"),
        ):
            decision = await self.approved()
            with patch.object(self.adapter, "call", side_effect=exception("private")):
                result = await self.gate.invoke(decision.decision_id)
            self.assertEqual(result.error_code, code)
            self.assertFalse(result.execution_uncertain)

    async def test_stop_checked_before_describe_or_schema_work(self):
        self.gate.emergency_disconnect()
        with patch.object(
            self.adapter, "describe", side_effect=AssertionError("network")
        ) as describe:
            with self.assertRaisesRegex(Exception, "emergency_disconnected"):
                await self.preflight()
            describe.assert_not_called()

    async def test_cancel_cleanup_failure_preserves_cancel(self):
        import asyncio

        decision = await self.approved()
        self.waiter = asyncio.Event()
        with patch.object(self.store, "finish", side_effect=RuntimeError("private")):
            task = asyncio.create_task(self.gate.invoke(decision.decision_id))
            while not self.calls:
                await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError) as cancelled:
                await task
        self.assertIn("sam_cleanup_failed", getattr(cancelled.exception, "__notes__", []))


class SupportedWireTests(GateTests):
    async def test_source_supported_uds_unknown_approval_invoke(self):
        import json

        from helpers.domain import DataClass, TransportConfig
        from helpers.gate import DelegationGate
        from helpers.remote_tools import RemoteTools
        from helpers.sam_client import SamClient
        from tests.fakes.sam_sidecar import FakeSamSidecar

        class Sidecar(FakeSamSidecar):
            def _response(self, method, target, headers, payload):
                if isinstance(payload, dict) and payload.get("method") == "tools/call":
                    if payload["params"]["name"] == "describe_remote_tool":
                        value = {
                            "peer_id": "peer-finance",
                            "tool_name": "mcp://finance/list-records",
                            "description": "Untrusted description",
                            "input_schema": {
                                "type": "object",
                                "properties": {"record": {"type": "string"}},
                                "required": ["record"],
                            },
                        }
                        return self._json(
                            200,
                            {
                                "jsonrpc": "2.0",
                                "id": payload["id"],
                                "result": {
                                    "content": [{"type": "text", "text": json.dumps(value)}]
                                },
                            },
                        )
                return super()._response(method, target, headers, payload)

        async with Sidecar(uds_path=self.tmp.name + "/node.sock") as server:
            self.config = replace(
                self.config,
                transport=TransportConfig("uds", server.base_url, server.uds_path, None),
            )
            async with SamClient(self.config.transport) as client:
                adapter = RemoteTools(client)
                gate = DelegationGate(
                    lambda: self.config, adapter, self.store, self.leases, self.audit
                )
                descriptor = await adapter.describe("peer-finance", "mcp://finance/list-records")
                self.assertEqual(descriptor.annotation_provenance, "unavailable")
                decision = await gate.preflight(
                    descriptor.peer_id,
                    descriptor.canonical_uri,
                    {"record": "public-value"},
                    DataClass.PUBLIC,
                )
                self.assertEqual(decision.outcome, "needs_approval")
                self.assertEqual(decision.risk_level.value, "unknown")
                self.assertEqual(
                    (await gate.invoke(decision.decision_id)).error_code, "approval_required"
                )
                gate.approve(decision.decision_id, approver_id="authenticated-operator")
                self.assertIsNone((await gate.invoke(decision.decision_id)).error_code)
                await gate.invoke(decision.decision_id)
            calls = [
                r["json"]["params"]
                for r in server.received
                if isinstance(r["json"], dict)
                and r["json"].get("method") == "tools/call"
                and r["json"]["params"]["name"] == "call_remote_tool"
            ]
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["arguments"]["arguments"], {"record": "public-value"})


def load_tests(loader, tests, pattern):
    """Run only new methods here; baseline suites run unchanged separately."""
    import unittest

    suite = unittest.TestSuite()
    for cls in list(globals().values()):
        if isinstance(cls, type) and cls.__module__ == __name__ and issubclass(cls, GateTests):
            for name in cls.__dict__:
                if name.startswith("test_"):
                    suite.addTest(cls(name))
    return suite


class WorkerTests(GateTests):
    async def test_process_stop_order_and_admitted_work(self):
        import subprocess
        import sys

        decision = await self.approved()
        payload = self.store.load(self.config.scope, decision.decision_id)
        self.store.claim(self.config.scope, decision.decision_id, 20, payload)
        generation = self.store.admit(self.config.scope, decision.decision_id, payload)
        script = """
import sys
from helpers.decisions import DecisionStore
from helpers.domain import Scope
store = DecisionStore(db_path=sys.argv[1], trusted_root=sys.argv[2])
store.revoke_scope(Scope('project', 'profile', 'other-chat'))
assert store.disabled(Scope('project', 'profile', 'never-seen'))
"""
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(self.store.storage.path_for_scope(self.config.scope)),
                self.tmp.name,
            ],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(self.store.disabled(self.config.scope))
        with self.assertRaises(Exception):
            self.store.admit(self.config.scope, decision.decision_id, payload)
        with self.store.transaction(self.config.scope) as db:
            row = db.execute(
                "SELECT generation FROM gate_admissions WHERE id=?",
                (self.store.digest(decision.decision_id),),
            ).fetchone()
        self.assertEqual(row[0], generation, "stop does not undo prior admissions")

    async def test_schema_rejection_matrix_is_bounded(self):
        import time

        from helpers.decisions import DecisionError
        from helpers.schema_guard import checked_schema

        cases = [
            {"pattern": "(a+)+$"},
            {"allOf": [{}]},
            {"anyOf": [{}]},
            {"$ref": "https://invalid/schema"},
            {"patternProperties": {".*": {}}},
            {"enum": list(range(33))},
            {"properties": {str(i): {} for i in range(65)}},
        ]
        started = time.monotonic()
        for schema in cases:
            with self.assertRaises(DecisionError):
                checked_schema(schema)
        self.assertLess(time.monotonic() - started, 0.2)


class FinalBoundaryTests(GateTests):
    async def test_public_model_invoke_rejects_sensitive_server_decision(self):
        from helpers import tool_runtime

        decision = await self.approved()
        with (
            patch.object(tool_runtime, "resolve_config", return_value=self.config),
            patch.object(
                tool_runtime, "scoped_stores", return_value=(self.store, self.leases, self.audit)
            ),
        ):
            value = await tool_runtime.dispatch(
                None, "sam_call_remote_tool", {"decision_id": decision.decision_id}
            )
        self.assertEqual(value["error_code"], "sensitive_payload_workflow_unsupported")

    async def test_schema_copy_rejects_deep_input_safely(self):
        from helpers.decisions import DecisionError
        from helpers.schema_guard import checked_schema

        schema = {}
        for _ in range(1100):
            schema = {"items": schema}
        with self.assertRaisesRegex(DecisionError, "unsupported_schema"):
            checked_schema(schema)


class FinalReviewTests(GateTests):
    async def test_schema_unsupported_is_visible_in_native_describe(self):
        from helpers import tool_runtime

        self.tool = _tool(self.tool.canonical_uri, {"pattern": "(a+)+$"})
        with (
            patch.object(tool_runtime, "resolve_config", return_value=self.config),
            patch("helpers.tool_runtime.RemoteTools.describe", return_value=self.tool),
        ):
            value = await tool_runtime.dispatch(
                None,
                "sam_describe_tool",
                {"peer_id": self.tool.peer_id, "tool_name": self.tool.canonical_uri},
            )
        self.assertEqual(value["error_code"], "unsupported_schema")
        self.assertEqual(value["status"], "unsupported")

    async def test_resolved_credential_sanitizes_all_native_payload_paths(self):
        from helpers import tool_runtime

        self.config = replace(
            self.config, transport=replace(self.config.transport, token="SENTINEL")
        )
        for name in ("sam_list_models", "sam_find_tools", "sam_describe_tool", "sam_route_preview"):
            with (
                patch.object(tool_runtime, "resolve_config", return_value=self.config),
                patch.object(
                    tool_runtime, "_dispatch", return_value={"SENTINEL": "free SENTINEL text"}
                ),
            ):
                value = await tool_runtime.dispatch(None, name, {})
            self.assertNotIn("SENTINEL", str(value))

    async def test_schema_keys_and_invalid_scalars_are_bounded(self):
        from helpers.decisions import DecisionError
        from helpers.schema_guard import checked_schema

        for value in (
            {"properties": {"x" * 17000: {}}},
            {"minimum": float("nan")},
            {"required": ["x"] * 100},
            {"type": ["string"] * 100},
        ):
            with self.assertRaises(DecisionError):
                checked_schema(value)


class AdmissionReviewTests(GateTests):
    async def test_admission_rechecks_expiry_after_claim_and_audit(self):
        from datetime import timedelta

        from helpers.decisions import DecisionError

        decision = await self.approved()
        payload = self.store.load(self.config.scope, decision.decision_id)
        self.store.claim(self.config.scope, decision.decision_id, 20, payload)
        self.now += timedelta(seconds=300)
        with self.assertRaisesRegex(DecisionError, "approval_expired"):
            self.store.admit(self.config.scope, decision.decision_id, payload)

    async def test_preflight_audit_failure_invalidates_orphan_decision(self):
        created = []
        original = self.store.create

        def create(scope, payload):
            identifier = original(scope, payload)
            created.append(identifier)
            return identifier

        with (
            patch.object(self.store, "create", side_effect=create),
            patch.object(self.audit, "append", side_effect=RuntimeError("private")),
        ):
            with self.assertRaises(Exception):
                await self.preflight()
        with self.assertRaises(Exception):
            self.store.load(self.config.scope, created[0])


class ConcurrentAdmissionTests(GateTests):
    async def test_two_worker_stop_and_admit_linearize_in_both_orders(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor

        from helpers.decisions import DecisionError, DecisionStore

        for stop_first in (True, False):
            scope = replace(self.config.scope, agent_profile="worker-" + str(stop_first))
            other = DecisionStore(
                db_path=self.store.storage.path_for_scope(scope),
                trusted_root=self.tmp.name,
                clock=lambda: self.now,
            )
            identifier = self.store.create(scope, {})
            payload = self.store.load(scope, identifier)
            self.store.claim(scope, identifier, 10, payload)
            first_done, second_ready = threading.Event(), threading.Event()

            def stop():
                if not stop_first:
                    second_ready.set()
                    if not first_done.wait(5):
                        raise AssertionError("admission worker stalled")
                other.revoke_scope(scope)
                if stop_first:
                    first_done.set()

            def admit():
                if stop_first:
                    second_ready.set()
                    if not first_done.wait(5):
                        raise AssertionError("stop worker stalled")
                try:
                    generation = self.store.admit(scope, identifier, payload)
                    return generation
                except DecisionError as exc:
                    return str(exc)
                finally:
                    if not stop_first:
                        first_done.set()

            with ThreadPoolExecutor(max_workers=2) as pool:
                waiting = pool.submit(admit if stop_first else stop)
                self.assertTrue(second_ready.wait(5))
                first = pool.submit(stop if stop_first else admit)
                first_result = first.result(timeout=10)
                second_result = waiting.result(timeout=10)
            self.assertEqual(
                second_result if stop_first else first_result,
                "emergency_disconnected" if stop_first else 0,
            )
            self.assertTrue(other.disabled(replace(scope, chat_id="new-chat")))


class CompletionRepairTests(GateTests):
    async def test_preflight_and_approval_denials_are_audited(self):
        self.tool = _tool(self.tool.canonical_uri, {"pattern": "(a+)+$"})
        with self.assertRaises(Exception):
            await self.preflight()
        with self.assertRaises(Exception):
            self.gate.approve("not-a-real-decision-identifier", approver_id="operator")
        events = self.audit.list_redacted(self.config.scope, limit=20)
        self.assertEqual([e["outcome"] for e in events], ["denial", "denial"])
        self.assertTrue(all(isinstance(e["latency_ms"], int) for e in events))

    async def test_bad_descriptor_value_error_permanently_invalidates(self):
        decision = await self.approved()
        with patch.object(self.adapter, "describe", side_effect=ValueError("invalid schema")):
            self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)
        self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)

    async def test_success_marks_admitted_and_stop_reports_inflight(self):
        import asyncio

        decision = await self.approved()
        self.waiter = asyncio.Event()
        task = asyncio.create_task(self.gate.invoke(decision.decision_id))
        while not self.calls:
            await asyncio.sleep(0)
        state = self.gate.emergency_disconnect()
        self.assertEqual(state["already_admitted"], 1)
        self.assertIs(state["mutations_undone"], False)
        self.waiter.set()
        result = await task
        self.assertTrue(result.admitted)
        self.assertIsNone(result.error_code)


class StatusTruthTests(GateTests):
    async def test_native_status_truthfully_labels_approval_route(self):
        from helpers import tool_runtime
        from helpers.sam_client import NodeHealth

        with (
            patch.object(tool_runtime, "resolve_config", return_value=self.config),
            patch("helpers.tool_runtime.SamClient.health", return_value=NodeHealth(True, {})),
            patch("helpers.tool_runtime.SamClient.list_models", return_value=[]),
        ):
            value = await tool_runtime.dispatch(None, "sam_mesh_status", {})
        self.assertEqual(value["guarded_invocation"], "public_single_use_approval")
        self.assertEqual(value["annotation_provenance"], "unavailable")

    async def test_direct_policy_checks_transport_before_schema_validation(self):
        self.config = replace(self.config, transport=replace(self.config.transport, type="http"))
        self.tool = _tool(self.tool.canonical_uri, {"pattern": "(a+)+$"})
        with patch("helpers.gate.validate_payload", side_effect=AssertionError("schema work")):
            decision = await self.preflight()
        self.assertEqual(decision.outcome, "deny")


class FinalErrorTests(GateTests):
    async def test_schema_failure_keeps_code_separate_from_uncertainty(self):
        decision = await self.approved()
        with patch.object(self.adapter, "call", side_effect=SamSchemaError("private")):
            value = await self.gate.invoke(decision.decision_id)
        self.assertEqual(value.error_code, "schema_changed")
        self.assertTrue(value.execution_uncertain)

    async def test_native_preflight_unsupported_schema_keeps_code(self):
        import json
        from types import SimpleNamespace

        from helpers import tool_runtime
        from helpers.decisions import DecisionError

        with patch.object(
            tool_runtime, "dispatch", side_effect=DecisionError("unsupported_schema")
        ):
            value = await tool_runtime.execute_native(
                SimpleNamespace(method=None, agent=None), "sam_mesh_status", {}
            )
        self.assertEqual(json.loads(value)["error_code"], "unsupported_schema")


class NativeCleanupTests(GateTests):
    async def test_client_close_failure_does_not_replace_primary_result(self):
        from helpers import tool_runtime
        from helpers.sam_client import NodeHealth

        with (
            patch.object(tool_runtime, "resolve_config", return_value=self.config),
            patch("helpers.tool_runtime.SamClient.health", return_value=NodeHealth(True, {})),
            patch("helpers.tool_runtime.SamClient.list_models", return_value=[]),
            patch("helpers.tool_runtime.SamClient.aclose", side_effect=RuntimeError("private")),
        ):
            value = await tool_runtime.dispatch(None, "sam_mesh_status", {})
        self.assertTrue(value["ready"])
        self.assertIn("client_cleanup_failed", value["degraded"])


class LastAuthorityTests(GateTests):
    async def test_cancelled_preflight_has_audit_record(self):
        import asyncio

        with patch.object(self.adapter, "describe", side_effect=asyncio.CancelledError()):
            with self.assertRaises(asyncio.CancelledError):
                await self.preflight()
        events = self.audit.list_redacted(self.config.scope, limit=5)
        self.assertEqual(events[0]["outcome"], "cancellation")

    async def test_unsupported_validation_permanently_invalidates(self):
        from helpers.decisions import DecisionError

        decision = await self.approved()
        with patch(
            "helpers.gate.validate_payload", side_effect=DecisionError("unsupported_schema")
        ):
            self.assertEqual(
                (await self.gate.invoke(decision.decision_id)).error_code, "unsupported_schema"
            )
        self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)

    async def test_ambiguous_schema_audit_marks_uncertainty(self):
        decision = await self.approved()
        with patch.object(self.adapter, "call", side_effect=SamSchemaError("private")):
            await self.gate.invoke(decision.decision_id)
        event = self.audit.list_redacted(self.config.scope, limit=1)[0]
        self.assertEqual(event["outcome"], "ambiguity")
        self.assertTrue(event["details"]["execution_uncertain"])


class ScopeOrderingTests(GateTests):
    async def test_scope_change_during_description_invalidates_original(self):
        original = self.config
        decision = await self.approved()

        async def describe(*args):
            self.config = replace(original, scope=replace(original.scope, chat_id="other"))
            return self.tool

        with patch.object(self.adapter, "describe", side_effect=describe):
            self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)
        self.config = original
        self.assertIsNotNone((await self.gate.invoke(decision.decision_id)).error_code)

    async def test_config_change_precedes_payload_validator(self):
        original = self.config
        decision = await self.approved()
        self.config = replace(original, features=replace(original.features, remote_calls=False))
        with patch("helpers.gate.validate_payload", side_effect=AssertionError("validation ran")):
            value = await self.gate.invoke(decision.decision_id)
        self.assertEqual(value.error_code, "schema_or_boundary_changed")
