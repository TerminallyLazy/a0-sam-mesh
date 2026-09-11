"""Protected SAM status endpoint."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class Status(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("status", input, request)
