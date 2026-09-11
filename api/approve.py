"""Protected SAM approve endpoint."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class Approve(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("approve", input, request)
