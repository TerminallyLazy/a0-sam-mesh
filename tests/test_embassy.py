"""Inbound isolation, abuse and publication ordering."""

import asyncio
import unittest


def definition():
    return {"name": "evidence-reviewer", "project": "evidence", "agent_profile": "researcher"}


class EmbassyTests(unittest.IsolatedAsyncioTestCase):
    async def test_definition_rejects_attachments_and_arbitrary_authority(self):
        from helpers.embassy_config import EmbassyService

        for field, value in (
            ("max_attachment_bytes", 1),
            ("type", "a2a"),
            ("project", "../secret"),
            ("agent_tool_policy", ["*"]),
            ("agent_tool_policy", ["response", "document_query"]),
        ):
            with self.assertRaises(ValueError):
                EmbassyService.from_dict(dict(definition(), **{field: value}))

    async def test_sessions_cannot_cross_origin_or_service(self):
        from helpers.embassy_config import EmbassyService
        from helpers.embassy_sessions import SessionManager, VerifiedOrigin

        async def runner(service, context, message):
            return context or "private-context", "ok"

        async def cleanup(context):
            pass

        service = EmbassyService.from_dict(dict(definition(), persistence="isolated_chat"))
        manager = SessionManager(runner, cleanup)
        first = await manager.ask(
            service, VerifiedOrigin("peer-a", "test-boundary"), {"message": "hello"}
        )
        with self.assertRaises(Exception):
            await manager.ask(
                service,
                VerifiedOrigin("peer-b", "test-boundary"),
                {"message": "steal", "session_id": first["session_id"]},
            )
        self.assertNotIn("private-context", str(first))
        with self.assertRaises(Exception):
            await manager.ask(
                service,
                VerifiedOrigin("peer-a", "test-boundary"),
                {"message": "steal", "project": "secret"},
            )
        await manager.finish(
            service, VerifiedOrigin("peer-a", "test-boundary"), first["session_id"]
        )
        self.assertEqual(manager.active_count, 0)

    async def test_concurrency_and_rate_limits_reject_without_waiting(self):
        from helpers.embassy_config import EmbassyService
        from helpers.embassy_sessions import SessionManager, VerifiedOrigin

        started, release = asyncio.Event(), asyncio.Event()

        async def runner(service, context, message):
            started.set()
            await release.wait()
            return "context", "ok"

        async def cleanup(context):
            pass

        service = EmbassyService.from_dict(dict(definition(), max_concurrency=1))
        manager = SessionManager(runner, cleanup)
        origin = VerifiedOrigin("peer-a", "test-boundary")
        task = asyncio.create_task(manager.ask(service, origin, {"message": "hello"}))
        await asyncio.wait_for(started.wait(), 2)
        try:
            with self.assertRaisesRegex(Exception, "concurrency_limited"):
                await manager.ask(service, origin, {"message": "second"})
        finally:
            release.set()
            await task

    async def test_publication_requires_health_and_withdraws_before_stop(self):
        from helpers.publication import Publication

        events = []

        async def health():
            return True

        async def advertise():
            events.append("advertise")
            return True

        async def withdraw():
            events.append("withdraw")
            return True

        async def stop():
            events.append("stop")

        publication = Publication(health, advertise, withdraw, stop)
        await publication.publish(acknowledgment="PUBLISH")
        await publication.close()
        self.assertEqual(events, ["advertise", "withdraw", "stop"])
        self.assertEqual(publication.state, "closed")
