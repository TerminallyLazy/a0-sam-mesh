"""Native Embassy service registry on one private, signature-protected UDS."""

import asyncio
import atexit
import base64
import json
import logging
import os
import socket
import stat
import threading
from dataclasses import dataclass
from pathlib import Path

from .decisions import DecisionError
from .embassy_broker import create_embassy_mcp
from .embassy_origin import CHALLENGE_PATH, OriginMiddleware, OriginVerifier
from .embassy_sessions import SessionManager, cleanup_agent, create_agent_context, run_agent

DRAIN_TIMEOUT = 30
CLEANUP_TIMEOUT = 5
SERVER_TIMEOUT = 5
STARTUP_TIMEOUT = 2
_LOG = logging.getLogger(__name__)


@dataclass
class RunningService:
    owner: tuple
    service: object
    manager: SessionManager
    app: object
    task: object
    stop: object
    guard: object
    state: str = "healthy_not_published"


class EmbassyRegistry:
    def __init__(self, public_key, *, runner=run_agent, cleanup=cleanup_agent, create_context=None):
        self.verifier = OriginVerifier(public_key)
        self.runner, self.cleanup = runner, cleanup
        self.create_context = create_context
        self.services = {}
        self.lock = asyncio.Lock()
        self.closing = False

    async def start(self, service, owner, guard):
        if not guard():
            raise DecisionError("inbound_publication_disabled")
        async with self.lock:
            if self.closing:
                raise DecisionError("embassy_runtime_unavailable")
            existing = self.services.get(service.name)
            if existing:
                if existing.owner != owner or existing.service != service:
                    raise DecisionError("service_name_in_use")
                return
            if len(self.services) >= 8:
                raise DecisionError("service_capacity_exceeded")
            manager = SessionManager(self.runner, self.cleanup, create_context=self.create_context)

            async def origin(request):
                if self.closing or not guard():
                    raise DecisionError("inbound_publication_disabled")
                return request.scope.get("sam_verified_origin")

            mcp = create_embassy_mcp(service, manager, origin)
            app = mcp.http_app(path=f"/{service.name}/mcp", stateless_http=True, json_response=True)
            ready = asyncio.get_running_loop().create_future()
            stop = asyncio.Event()

            async def lifecycle():
                try:
                    # FastMCP ContextVar tokens and AnyIO cancel scopes belong to
                    # this task for their entire lifetime, including teardown.
                    async with asyncio.timeout(None) as lifetime:
                        async with app.router.lifespan_context(app):
                            ready.set_result(None)
                            try:
                                await stop.wait()
                            finally:
                                lifetime.reschedule(
                                    asyncio.get_running_loop().time()
                                    + DRAIN_TIMEOUT
                                    + 2 * CLEANUP_TIMEOUT
                                )
                                manager.accepting = False
                                try:
                                    async with asyncio.timeout(DRAIN_TIMEOUT):
                                        await manager.drain(timeout=DRAIN_TIMEOUT)
                                finally:
                                    async with asyncio.timeout(CLEANUP_TIMEOUT):
                                        tasks = list(manager.tasks)
                                        for task in tasks:
                                            task.cancel()
                                        await asyncio.gather(*tasks, return_exceptions=True)
                                        results = await asyncio.gather(
                                            *(
                                                manager._remove(key)
                                                for key in list(manager.sessions)
                                            ),
                                            return_exceptions=True,
                                        )
                                        if any(
                                            isinstance(result, BaseException) for result in results
                                        ):
                                            _LOG.error("Embassy context cleanup failed")
                except BaseException as exc:
                    if not ready.done():
                        ready.set_exception(exc)
                    raise

            task = asyncio.create_task(lifecycle(), name=f"embassy-service-{service.name}")
            record = RunningService(
                owner,
                service,
                manager,
                OriginMiddleware(app, service.name, self.verifier),
                task,
                stop,
                guard,
            )
            try:
                await asyncio.shield(ready)
                if self.closing:
                    raise DecisionError("embassy_runtime_unavailable")
                if not guard():
                    raise DecisionError("inbound_publication_disabled")
            except BaseException:
                stop.set()
                await asyncio.gather(task, return_exceptions=True)
                raise
            self.services[service.name] = record

    def status(self, owner):
        return [
            {
                "name": value.service.name,
                "state": value.state,
                "active_sessions": value.manager.active_count,
                "accepting": value.manager.accepting,
                "origin_boundary": self.verifier.boundary,
            }
            for value in self.services.values()
            if value.owner == owner
        ]

    async def close(self, name, owner):
        async with self.lock:
            record = self.services.get(name)
            if record is None:
                return
            if record.owner != owner:
                raise DecisionError("service_scope_denied")
            record.state = "draining"
            record.manager.accepting = False
            record.stop.set()
        try:
            await asyncio.shield(record.task)
        except asyncio.CancelledError:
            # Caller cancellation must not orphan this task's owned lifespan.
            await asyncio.gather(record.task, return_exceptions=True)
            raise
        finally:
            if record.task.done() and self.services.get(name) is record:
                self.services.pop(name, None)

    async def close_all(self):
        # Revoke admission before waiting for a start's readiness. The lock
        # joins every in-flight start before the final drain snapshot; start
        # rechecks closing and tears down its owner instead of registering late.
        self.closing = True
        async with self.lock:
            records = list(self.services.items())
            for _name, record in records:
                record.state = "draining"
                record.manager.accepting = False
                record.stop.set()
        results = await asyncio.gather(
            *(self.close(name, record.owner) for name, record in records),
            return_exceptions=True,
        )
        if any(isinstance(result, BaseException) for result in results):
            _LOG.error("Embassy service cleanup failed")

    async def maintenance(self):
        while True:
            await asyncio.sleep(5)
            for name, record in list(self.services.items()):
                try:
                    allowed = record.guard()
                except Exception:
                    allowed = False
                if not allowed:
                    try:
                        await self.close(name, record.owner)
                    except Exception:
                        _LOG.error("Embassy revoked service cleanup failed")
                    continue
                for identifier, session in list(record.manager.sessions.items()):
                    if not session.active and session.expires <= record.manager.clock():
                        try:
                            await record.manager._remove(identifier)
                        except Exception:
                            _LOG.error("Embassy expired context cleanup failed")

    async def __call__(self, scope, receive, send):
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] != "http":
            return
        path = scope.get("path", "")
        if (
            path == CHALLENGE_PATH
            and scope.get("method") == "GET"
            and not scope.get("query_string")
        ):
            body = json.dumps(
                {"challenge": self.verifier.challenge}, separators=(",", ":")
            ).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"cache-control", b"no-store"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        parts = path.split("/")
        record = self.services.get(parts[1]) if len(parts) == 3 and parts[2] == "mcp" else None
        if not self.closing and record and record.state != "draining":
            try:
                allowed = record.guard()
            except Exception:
                allowed = False
            if allowed:
                return await record.app(scope, receive, send)
        await send({"type": "http.response.start", "status": 404, "headers": []})
        await send({"type": "http.response.body", "body": b""})


def _deployment():
    """Operator provisioned immutable trust key and private socket directory."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    public_file = Path(
        os.environ.get("SAM_EMBASSY_PUBLIC_KEY_FILE", "/run/sam-embassy-trust/public.key")
    )
    socket_path = Path(os.environ.get("SAM_EMBASSY_SOCKET", "/run/sam-embassy/broker.sock"))
    for path in (public_file, socket_path.parent):
        if not path.is_absolute() or path.resolve() != path:
            raise DecisionError("embassy_deployment_unavailable")
        metadata = path.lstat()
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise DecisionError("embassy_deployment_unavailable")
    if not public_file.is_file() or not socket_path.parent.is_dir():
        raise DecisionError("embassy_deployment_unavailable")
    if stat.S_IMODE(socket_path.parent.stat().st_mode) != 0o700:
        raise DecisionError("embassy_deployment_unavailable")
    raw = public_file.read_bytes()
    if len(raw) > 128:
        raise DecisionError("embassy_deployment_unavailable")
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(raw.strip(), validate=True))
    return key, socket_path


def deployment_status():
    try:
        _deployment()
        return {
            "available": True,
            "transport": "signed_mcp_http",
            "requires_isolated_gateway": True,
        }
    except Exception:
        return {"available": False, "reason": "embassy_deployment_unavailable"}


class EmbassyRuntime:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.registry = None
        self.server = None

        def run_loop():
            try:
                self.loop.run_forever()
            finally:
                self.loop.close()

        self.thread = threading.Thread(target=run_loop, name="sam-embassy", daemon=True)
        self.thread.start()
        self.start_lock = None
        self.closed = False

    async def _ensure(self):
        import uvicorn

        if self.start_lock is None:
            self.start_lock = asyncio.Lock()
        async with self.start_lock:
            if getattr(self, "closed", False):
                raise DecisionError("embassy_runtime_unavailable")
            if self.registry is not None:
                return self.registry
            key, path = _deployment()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            identity = server = server_task = None
            try:
                # Refuse an existing socket rather than unlinking another runtime.
                listener.bind(str(path))
                metadata = path.lstat()
                identity = (metadata.st_dev, metadata.st_ino)
                os.chmod(path, 0o600)
                listener.listen(64)
                listener.setblocking(False)
                registry = EmbassyRegistry(key, create_context=create_agent_context)
                server = uvicorn.Server(
                    uvicorn.Config(
                        registry,
                        lifespan="off",
                        access_log=False,
                        proxy_headers=False,
                        log_level="error",
                        limit_concurrency=32,
                        timeout_graceful_shutdown=SERVER_TIMEOUT,
                    )
                )
                server_task = asyncio.create_task(server.serve(sockets=[listener]))
                for _ in range(max(1, int(STARTUP_TIMEOUT / 0.02))):
                    if server.started:
                        break
                    if server_task.done():
                        await server_task
                        raise DecisionError("embassy_runtime_unavailable")
                    await asyncio.sleep(0.02)
                if not server.started:
                    server.should_exit = True
                    raise DecisionError("embassy_runtime_unavailable")
                self.registry, self.server, self.path = registry, server, path
                self.server_task, self.listener, self.socket_identity = (
                    server_task,
                    listener,
                    identity,
                )
                self.maintenance_task = asyncio.create_task(registry.maintenance())
                return registry
            except BaseException:
                try:
                    await _stop_server(server, server_task)
                finally:
                    listener.close()
                    _unlink_owned(path, identity)
                raise

    async def submit(self, operation, *args):
        if self.closed:
            raise DecisionError("embassy_runtime_unavailable")

        async def perform():
            if operation == "status" and self.registry is None:
                return []
            if operation in {"close", "close_scope"} and self.registry is None:
                return None
            registry = await self._ensure()
            if operation == "status":
                return registry.status(*args)
            if operation == "close_scope":
                for name, record in list(registry.services.items()):
                    if record.owner == args[0]:
                        await registry.close(name, args[0])
                return None
            return await getattr(registry, operation)(*args)

        return await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(perform(), self.loop))

    async def _shutdown(self):
        if self.start_lock is None:
            self.start_lock = asyncio.Lock()
        async with self.start_lock:
            if self.registry is None:
                return
            try:
                self.maintenance_task.cancel()
                await asyncio.gather(
                    self.maintenance_task, self.registry.close_all(), return_exceptions=True
                )
            finally:
                try:
                    await _stop_server(self.server, self.server_task)
                finally:
                    self.listener.close()
                    _unlink_owned(self.path, self.socket_identity)
                    self.registry = None

    def shutdown(self):
        if self.closed:
            return
        self.closed = True
        if self.loop.is_running():
            future = asyncio.run_coroutine_threadsafe(self._shutdown(), self.loop)
            try:
                future.result(timeout=DRAIN_TIMEOUT + 3 * CLEANUP_TIMEOUT + SERVER_TIMEOUT)
            except TimeoutError:
                # Never stop the loop underneath in-flight context/lifespan
                # cleanup. Completion, even after the deadline, owns loop stop.
                future.add_done_callback(lambda _: self.loop.call_soon_threadsafe(self.loop.stop))
                _LOG.error("Embassy shutdown exceeded cleanup deadline")
                return
            except Exception:
                _LOG.error("Embassy shutdown cleanup failed")
            finally:
                if future.done():
                    self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(timeout=CLEANUP_TIMEOUT)


def _unlink_owned(path, identity):
    if identity is None:
        return
    try:
        metadata = path.lstat()
        if stat.S_ISSOCK(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == identity:
            path.unlink()
    except FileNotFoundError:
        pass


async def _stop_server(server, task):
    if task is None:
        return
    server.should_exit = True
    try:
        await asyncio.wait_for(asyncio.shield(task), SERVER_TIMEOUT)
    except (TimeoutError, asyncio.CancelledError):
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    except Exception:
        _LOG.error("Embassy server teardown failed")


_runtime = None
_runtime_lock = threading.Lock()


def runtime():
    global _runtime
    with _runtime_lock:
        if _runtime is None or (_runtime.closed and not _runtime.thread.is_alive()):
            _runtime = EmbassyRuntime()
            atexit.register(_runtime.shutdown)
        return _runtime
