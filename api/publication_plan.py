"""Protected SAM publication plan endpoint."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class PublicationPlan(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("publication_plan", input, request)
