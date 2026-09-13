"""Three-tool FastMCP broker; verified origin comes from trusted ASGI middleware."""

from .decisions import DecisionError
from .embassy_config import BROKER_TOOLS, HTTP_CONTRACT_MARKER
from .embassy_sessions import VerifiedOrigin


def create_embassy_mcp(service, manager, origin_resolver):
    from fastmcp import FastMCP
    from fastmcp.server.dependencies import get_http_request

    if not callable(origin_resolver):
        raise DecisionError("verified_origin_boundary_unavailable")
    mcp = FastMCP(name=service.name)

    async def origin():
        # Never read X-Peer-Id directly: loopback clients can spoof it. The resolver
        # must authenticate the SAM-to-broker transport before trusting SAM attribution.
        value = await origin_resolver(get_http_request())
        if type(value) is not VerifiedOrigin:
            raise DecisionError("verified_origin_required")
        return value

    @mcp.tool(
        description=HTTP_CONTRACT_MARKER + "Inspect this bounded specialist service.",
        annotations={"readOnlyHint": True},
    )
    async def service_info() -> dict:
        await origin()
        return {
            "name": service.name,
            "description": service.description,
            "tools": list(BROKER_TOOLS),
            "attachments": False,
            "max_input_bytes": service.max_input_bytes,
            "max_runtime_seconds": service.max_runtime_seconds,
        }

    @mcp.tool(
        description=HTTP_CONTRACT_MARKER
        + "Ask the configured specialist within its published limits.",
        annotations={"readOnlyHint": False, "idempotentHint": False},
    )
    async def ask_specialist(message: str, session_id: str | None = None) -> dict:
        request = {"message": message}
        if session_id is not None:
            request["session_id"] = session_id
        return await manager.ask(service, await origin(), request)

    @mcp.tool(
        description=HTTP_CONTRACT_MARKER + "Finish your own isolated specialist session.",
        annotations={"readOnlyHint": False, "idempotentHint": False},
    )
    async def finish_session(session_id: str) -> dict:
        return await manager.finish(service, await origin(), session_id)

    return mcp
