"""Protected SAM native mcp plan endpoint."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class NativeMcpPlan(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("native_mcp_plan", input, request)
