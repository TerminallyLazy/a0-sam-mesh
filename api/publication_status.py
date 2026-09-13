"""Scoped Embassy runtime status."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class PublicationStatus(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("publication_status", input, request)
