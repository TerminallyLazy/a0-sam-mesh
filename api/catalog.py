"""Protected SAM catalog endpoint."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class Catalog(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("catalog", input, request)
