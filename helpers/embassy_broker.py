"""Three-tool FastMCP broker; verified origin comes from trusted ASGI middleware."""

from .decisions import DecisionError
from .embassy_config import BROKER_TOOLS, HTTP_CONTRACT_MARKER
from .embassy_sessions import VerifiedOrigin


def create_embassy_mcp(service, manager, origin_resolver):
    from fastmcp import FastMCP
    from fastmcp.server.dependencies import get_http_request
    from fastmcp.tools import Tool

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

    async def ask_specialist(message: str, session_id: str = "") -> dict:
        request = {"message": message}
        if session_id:
            request["session_id"] = session_id
        return await manager.ask(service, await origin(), request)

    ask_tool = Tool.from_function(
        ask_specialist,
        description=HTTP_CONTRACT_MARKER
        + "Ask the configured specialist within its published limits. "
        + "Omit session_id or use an empty string to start a new session.",
        annotations={"readOnlyHint": False, "idempotentHint": False},
    )
    # The Python default supports omitted sessions at invocation. JSON Schema's
    # default is only an annotation and lies outside our governed subset.
    ask_tool.parameters["properties"]["session_id"].pop("default", None)
    mcp.add_tool(ask_tool)

    @mcp.tool(
        description=HTTP_CONTRACT_MARKER + "Finish your own isolated specialist session.",
        annotations={"readOnlyHint": False, "idempotentHint": False},
    )
    async def finish_session(session_id: str) -> dict:
        return await manager.finish(service, await origin(), session_id)

    return mcp
