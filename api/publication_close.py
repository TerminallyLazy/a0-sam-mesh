"""Scoped, offline-safe Embassy admission closure and session drain."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class PublicationClose(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("publication_close", input, request)
