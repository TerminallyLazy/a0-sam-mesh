"""Protected control plane binding and offline operation."""

from unittest.mock import patch

from tests.test_gate import GateTests


class ControlTests(GateTests):
    async def test_native_admission_is_counted_and_stop_blocks_new_admission(self):
        scope = self.config.scope
        admission = self.store.begin_native(scope, 10)
        state = self.store.revoke_scope(scope)
        self.assertEqual(state["already_admitted"], 1)
        with self.assertRaisesRegex(Exception, "emergency_disconnected"):
            self.store.begin_native(scope, 10)
        self.store.finish(scope, admission)
        self.assertEqual(self.store.revoke_scope(scope)["already_admitted"], 0)

    async def test_review_never_returns_arguments_or_lease(self):
        from helpers.control import review_decision

        decision = await self.preflight()
        review = review_decision(self.store, self.config.scope, decision.decision_id)
        self.assertEqual(review["peer_id"], self.tool.peer_id)
        self.assertNotIn("private-sentinel", str(review))
        self.assertNotIn("lease_id", review)
        self.assertEqual(review["data_class"], "internal")

    async def test_approval_requires_exact_typed_acknowledgment(self):
        from helpers.control import approve_decision

        decision = await self.preflight()
        with self.assertRaises(Exception):
            approve_decision(self.gate, decision.decision_id, "yes", "operator")
        self.assertEqual(
            (await self.gate.invoke(decision.decision_id)).error_code, "approval_required"
        )
        approve_decision(self.gate, decision.decision_id, "APPROVE", "operator")
        self.assertIsNone((await self.gate.invoke(decision.decision_id)).error_code)

    async def test_emergency_uses_scope_even_if_config_is_broken(self):
        from helpers.control import stop_scope

        with patch.object(self.gate, "resolve", side_effect=ValueError("bad config")):
            stopped = stop_scope(self.config.scope, (self.store, self.leases, self.audit))
        self.assertTrue(stopped["stopped"])
        self.assertTrue(self.store.disabled(self.config.scope))

    async def test_resume_does_not_restore_an_old_approval_in_another_chat(self):
        from dataclasses import replace

        from helpers.control import resume_scope, stop_scope

        scope = self.config.scope
        other_chat = replace(scope, chat_id="other-chat")
        identifier = self.store.create(other_chat, {"test": "old approval"})
        stop_scope(scope, (self.store, self.leases, self.audit))
        self.assertTrue(self.store.disabled(other_chat))
        with self.assertRaisesRegex(Exception, "acknowledgment_required"):
            resume_scope(scope, (self.store, self.leases, self.audit), "yes")
        resume_scope(scope, (self.store, self.leases, self.audit), "RESUME")
        self.assertFalse(self.store.disabled(other_chat))
        with self.assertRaisesRegex(Exception, "decision_replayed"):
            self.store.load(other_chat, identifier)
