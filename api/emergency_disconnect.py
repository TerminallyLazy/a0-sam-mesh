"""Protected SAM emergency disconnect endpoint."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class EmergencyDisconnect(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("emergency_disconnect", input, request)
