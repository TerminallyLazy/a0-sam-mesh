"""Authenticated operator start for an explicitly allowlisted specialist."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class PublicationStart(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("publication_start", input, request)
