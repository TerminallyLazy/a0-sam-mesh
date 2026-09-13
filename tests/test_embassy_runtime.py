"""Runtime lifecycle and request isolation across actual ASGI MCP requests."""

import json
import unittest

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class EmbassyRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_registry_lifecycle_authenticated_call_and_shutdown(self):
        from helpers.embassy_config import EmbassyService
        from helpers.embassy_origin import OriginSigner
        from helpers.embassy_runtime import EmbassyRegistry

        key = Ed25519PrivateKey.generate()
        signer = OriginSigner(key)
        seen = []

        async def runner(service, context, message):
            seen.append(message)
            return "isolated", "answer"

        async def cleanup(context):
            seen.append("cleaned")

        registry = EmbassyRegistry(key.public_key(), runner=runner, cleanup=cleanup)
        service = EmbassyService("research-desk", "research", "specialist")
        await registry.start(service, ("research", "specialist"), lambda: True)
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=registry), base_url="http://localhost"
        )
        path = "/research-desk/mcp"

        async def call(peer, method, params):
            body = json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            ).encode()
            return await client.post(
                path,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "x-sam-embassy-proof": signer.sign(
                        peer, service.name, "POST", path, body, audience=registry.verifier.challenge
                    ),
                },
            )

        try:
            anon = await call(
                "", "tools/call", {"name": "ask_specialist", "arguments": {"message": "denied"}}
            )
            self.assertEqual(anon.status_code, 401)
            peer = "12D3KooW" + "A" * 44
            result = await call(
                peer, "tools/call", {"name": "ask_specialist", "arguments": {"message": "hello"}}
            )
            self.assertEqual(result.status_code, 200, result.text)
            self.assertFalse(result.json()["result"].get("isError"))
            self.assertEqual(seen, ["hello", "cleaned"])
            with self.assertRaisesRegex(Exception, "service_scope_denied"):
                await registry.close(service.name, ("other", "specialist"))
            await registry.close(service.name, ("research", "specialist"))
            self.assertEqual((await call(peer, "tools/list", {})).status_code, 404)
        finally:
            await client.aclose()
            await registry.close_all()

    async def test_disabled_owner_stops_admission(self):
        from helpers.embassy_config import EmbassyService
        from helpers.embassy_runtime import EmbassyRegistry

        registry = EmbassyRegistry(Ed25519PrivateKey.generate().public_key())
        with self.assertRaisesRegex(Exception, "inbound_publication_disabled"):
            await registry.start(
                EmbassyService("research-desk", "research", "specialist"),
                ("research", "specialist"),
                lambda: False,
            )
        self.assertEqual(registry.status(("research", "specialist")), [])

    async def test_lifespan_start_and_close_in_distinct_tasks(self):
        import asyncio

        from helpers.embassy_config import EmbassyService
        from helpers.embassy_runtime import EmbassyRegistry

        registry = EmbassyRegistry(Ed25519PrivateKey.generate().public_key())
        owner = ("research", "specialist")
        service = EmbassyService("research-desk", *owner)
        await asyncio.create_task(registry.start(service, owner, lambda: True))
        await asyncio.create_task(registry.close(service.name, owner))
        self.assertEqual(registry.services, {})

    async def test_failed_bind_startup_removes_owned_socket_and_allows_retry(self):
        import asyncio
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from helpers.embassy_runtime import EmbassyRuntime

        runtime = EmbassyRuntime.__new__(EmbassyRuntime)
        runtime.start_lock = runtime.registry = None
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broker.sock"
            with patch(
                "helpers.embassy_runtime._deployment",
                return_value=(Ed25519PrivateKey.generate().public_key(), path),
            ):
                with patch("uvicorn.Config", side_effect=RuntimeError("injected startup failure")):
                    with self.assertRaisesRegex(RuntimeError, "injected startup failure"):
                        await runtime._ensure()
                self.assertFalse(path.exists())
                await runtime._ensure()
                await asyncio.wait_for(runtime._shutdown(), 3)
                self.assertFalse(path.exists())

    async def test_close_all_drains_services_concurrently_even_if_cleanup_fails(self):
        import asyncio

        from helpers.embassy_config import EmbassyService
        from helpers.embassy_runtime import EmbassyRegistry

        registry = EmbassyRegistry(Ed25519PrivateKey.generate().public_key())
        started, cleaned = set(), set()
        both = asyncio.Event()
        owner = ("research", "specialist")
        for name in ("one-desk", "two-desk"):
            await registry.start(EmbassyService(name, *owner), owner, lambda: True)

            async def drain(timeout, name=name):
                started.add(name)
                if len(started) == 2:
                    both.set()
                await asyncio.wait_for(both.wait(), 0.5)
                cleaned.add(name)
                if name == "one-desk":
                    raise RuntimeError("cleanup failure")

            registry.services[name].manager.drain = drain
        await registry.close_all()
        self.assertEqual(cleaned, {"one-desk", "two-desk"})
        self.assertEqual(registry.services, {})

    async def test_startup_timeout_and_cancellation_await_server_and_remove_socket(self):
        import asyncio
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from helpers.embassy_runtime import EmbassyRuntime

        entered, exited = asyncio.Event(), asyncio.Event()

        class Server:
            started = False
            should_exit = False

            def __init__(self, config):
                pass

            async def serve(self, sockets):
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    exited.set()

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broker.sock"
            with (
                patch(
                    "helpers.embassy_runtime._deployment",
                    return_value=(Ed25519PrivateKey.generate().public_key(), path),
                ),
                patch("uvicorn.Server", Server),
                patch("helpers.embassy_runtime.STARTUP_TIMEOUT", 0.02),
                patch("helpers.embassy_runtime.SERVER_TIMEOUT", 0.02),
            ):
                for cancelled in (False, True):
                    runtime = EmbassyRuntime.__new__(EmbassyRuntime)
                    runtime.start_lock = runtime.registry = None
                    entered.clear()
                    exited.clear()
                    task = asyncio.create_task(runtime._ensure())
                    await entered.wait()
                    if cancelled:
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                    else:
                        with self.assertRaisesRegex(Exception, "embassy_runtime_unavailable"):
                            await task
                    self.assertTrue(exited.is_set())
                    self.assertFalse(path.exists())

    async def test_preexisting_and_replaced_sockets_are_preserved(self):
        import socket
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from helpers.embassy_runtime import EmbassyRuntime, _unlink_owned

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broker.sock"
            with (
                socket.socket(socket.AF_UNIX) as first,
                socket.socket(socket.AF_UNIX) as replacement,
            ):
                first.bind(str(path))
                identity = (path.stat().st_dev, path.stat().st_ino)
                runtime = EmbassyRuntime.__new__(EmbassyRuntime)
                runtime.start_lock = runtime.registry = None
                with patch(
                    "helpers.embassy_runtime._deployment",
                    return_value=(Ed25519PrivateKey.generate().public_key(), path),
                ):
                    with self.assertRaises(OSError):
                        await runtime._ensure()
                self.assertEqual(path.stat().st_ino, identity[1])
                path.unlink()
                replacement.bind(str(path))
                _unlink_owned(path, identity)
                self.assertTrue(path.exists())

    async def test_guard_revocation_maintenance_closes_owning_lifespan(self):
        import asyncio
        from unittest.mock import patch

        from helpers.embassy_config import EmbassyService
        from helpers.embassy_runtime import EmbassyRegistry

        registry = EmbassyRegistry(Ed25519PrivateKey.generate().public_key())
        owner = ("research", "specialist")
        allowed = True
        await asyncio.create_task(
            registry.start(EmbassyService("research-desk", *owner), owner, lambda: allowed)
        )
        task = registry.services["research-desk"].task
        allowed = False
        original_sleep = asyncio.sleep

        async def fast_sleep(seconds):
            await original_sleep(0.001)

        with patch("helpers.embassy_runtime.asyncio.sleep", fast_sleep):
            maintenance = asyncio.create_task(registry.maintenance())
            try:
                await asyncio.wait_for(asyncio.shield(task), 1)
                await original_sleep(0.01)
                self.assertEqual(registry.services, {})
                self.assertFalse(maintenance.done())
            finally:
                maintenance.cancel()
                await asyncio.gather(maintenance, return_exceptions=True)

    async def test_cancelled_close_still_finishes_lifespan(self):
        import asyncio

        from helpers.embassy_config import EmbassyService
        from helpers.embassy_runtime import EmbassyRegistry

        registry = EmbassyRegistry(Ed25519PrivateKey.generate().public_key())
        owner = ("research", "specialist")
        await registry.start(EmbassyService("research-desk", *owner), owner, lambda: True)
        entered, finish = asyncio.Event(), asyncio.Event()

        async def drain(timeout):
            entered.set()
            await finish.wait()

        record = registry.services["research-desk"]
        record.manager.drain = drain
        close = asyncio.create_task(registry.close("research-desk", owner))
        await entered.wait()
        close.cancel()
        finish.set()
        with self.assertRaises(asyncio.CancelledError):
            await close
        self.assertTrue(record.task.done())
        self.assertEqual(registry.services, {})

    async def test_thread_shutdown_concurrent_busy_contexts_socket_and_loop_cleanup(self):
        import asyncio
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from helpers.embassy_config import EmbassyService
        from helpers.embassy_runtime import EmbassyRuntime
        from helpers.embassy_sessions import VerifiedOrigin

        owner = ("research", "specialist")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broker.sock"
            with (
                patch(
                    "helpers.embassy_runtime._deployment",
                    return_value=(Ed25519PrivateKey.generate().public_key(), path),
                ),
                patch("helpers.embassy_runtime.DRAIN_TIMEOUT", 0.05),
            ):
                runtime = EmbassyRuntime()
                cleaned = []

                async def setup():
                    registry = await runtime._ensure()

                    async def runner(service, context, message):
                        await asyncio.Event().wait()

                    async def cleanup(context):
                        cleaned.append(context)
                        if context == "one-desk":
                            raise RuntimeError("one cleanup failed")

                    registry.runner, registry.cleanup = runner, cleanup
                    registry.create_context = lambda service: service.name
                    asks = []
                    for name in ("one-desk", "two-desk"):
                        service = EmbassyService(name, *owner)
                        await registry.start(service, owner, lambda: True)
                        manager = registry.services[name].manager
                        asks.append(
                            asyncio.create_task(
                                manager.ask(
                                    service, VerifiedOrigin("peer", "boundary"), {"message": "busy"}
                                )
                            )
                        )
                    await asyncio.sleep(0.01)
                    return asks, [record.task for record in registry.services.values()]

                asks, lifespans = await asyncio.wrap_future(
                    asyncio.run_coroutine_threadsafe(setup(), runtime.loop)
                )
                await asyncio.to_thread(runtime.shutdown)
                self.assertCountEqual(cleaned, ["one-desk", "two-desk"])
                self.assertTrue(all(task.done() for task in asks + lifespans))
                for task in asks:
                    if not task.cancelled():
                        task.exception()
                self.assertFalse(runtime.thread.is_alive())
                self.assertTrue(runtime.loop.is_closed())
                self.assertFalse(path.exists())
                self.assertIsNone(runtime.registry)

    async def test_challenge_endpoint_exact_get_without_body_read(self):
        from helpers.embassy_runtime import EmbassyRegistry

        registry = EmbassyRegistry(Ed25519PrivateKey.generate().public_key())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=registry), base_url="http://broker"
        ) as client:
            result = await client.get("/__embassy_challenge")
            self.assertEqual(result.json(), {"challenge": registry.verifier.challenge})
            self.assertLess(len(result.content), 128)
            self.assertEqual(result.headers["cache-control"], "no-store")
            for method, path in [
                ("POST", "/__embassy_challenge"),
                ("GET", "/__embassy_challenge?audience=x"),
                ("GET", "/__embassy_challenge/"),
            ]:
                self.assertEqual((await client.request(method, path)).status_code, 404)

    async def test_offline_close_is_idempotent_without_deployment(self):
        import asyncio
        from unittest.mock import patch

        from helpers.embassy_runtime import EmbassyRuntime

        with patch(
            "helpers.embassy_runtime._deployment",
            side_effect=AssertionError("offline close must not start broker"),
        ):
            runtime = EmbassyRuntime()
            try:
                self.assertIsNone(
                    await runtime.submit("close", "research-desk", ("research", "specialist"))
                )
                self.assertIsNone(runtime.registry)
            finally:
                await asyncio.to_thread(runtime.shutdown)

    async def test_shutdown_waits_for_inflight_start_and_prevents_late_lifespan_registration(self):
        import asyncio
        from contextlib import asynccontextmanager
        from unittest.mock import patch

        from helpers.embassy_config import EmbassyService
        from helpers.embassy_runtime import EmbassyRegistry, create_embassy_mcp

        registry = EmbassyRegistry(Ed25519PrivateKey.generate().public_key())
        owner = ("research", "specialist")
        service = EmbassyService("research-desk", *owner)
        entered, release, shutdown_entered, exited = (
            asyncio.Event(),
            asyncio.Event(),
            asyncio.Event(),
            asyncio.Event(),
        )
        lifecycle_tasks = []

        def controlled_mcp(*args, **kwargs):
            mcp = create_embassy_mcp(*args, **kwargs)
            original_http_app = mcp.http_app

            def http_app(*args, **kwargs):
                app = original_http_app(*args, **kwargs)
                original_lifespan = app.router.lifespan_context

                @asynccontextmanager
                async def lifespan(app):
                    lifecycle_tasks.append(asyncio.current_task())
                    async with original_lifespan(app):
                        entered.set()
                        await release.wait()
                        try:
                            yield
                        finally:
                            exited.set()

                app.router.lifespan_context = lifespan
                return app

            mcp.http_app = http_app
            return mcp

        async def shutdown():
            shutdown_entered.set()
            await registry.close_all()

        with patch("helpers.embassy_runtime.create_embassy_mcp", controlled_mcp):
            starting = asyncio.create_task(registry.start(service, owner, lambda: True))
            await entered.wait()
            closing = asyncio.create_task(shutdown())
            await shutdown_entered.wait()
            try:
                self.assertFalse(closing.done(), "shutdown returned while a lifespan was entering")
                release.set()
                results = await asyncio.gather(starting, closing, return_exceptions=True)
                self.assertEqual(str(results[0]), "embassy_runtime_unavailable")
                self.assertIsNone(results[1])
                self.assertEqual(registry.services, {})
                self.assertTrue(exited.is_set())
                self.assertTrue(all(task.done() for task in lifecycle_tasks))
                with self.assertRaisesRegex(Exception, "embassy_runtime_unavailable"):
                    await registry.start(service, owner, lambda: True)
            finally:
                release.set()
                await asyncio.gather(starting, closing, return_exceptions=True)
                await registry.close_all()

    async def test_single_service_close_preserves_manual_restart(self):
        import asyncio

        from helpers.embassy_config import EmbassyService
        from helpers.embassy_runtime import EmbassyRegistry

        registry = EmbassyRegistry(Ed25519PrivateKey.generate().public_key())
        owner = ("research", "specialist")
        service = EmbassyService("research-desk", *owner)
        try:
            await asyncio.create_task(registry.start(service, owner, lambda: True))
            first = registry.services[service.name].task
            await asyncio.create_task(registry.close(service.name, owner))
            await asyncio.create_task(registry.start(service, owner, lambda: True))
            self.assertTrue(first.done())
            self.assertIsNot(registry.services[service.name].task, first)
            self.assertTrue(registry.services[service.name].manager.accepting)
        finally:
            await registry.close_all()
