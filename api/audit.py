"""Protected SAM audit endpoint."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class Audit(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("audit", input, request)
