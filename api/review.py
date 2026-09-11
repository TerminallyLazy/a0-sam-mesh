"""Protected SAM review endpoint."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class Review(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("review", input, request)
