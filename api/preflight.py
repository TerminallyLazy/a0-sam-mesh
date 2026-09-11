"""Protected SAM preflight endpoint."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class Preflight(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("preflight", input, request)
