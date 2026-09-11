"""Protected SAM route preview endpoint."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class RoutePreview(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("route_preview", input, request)
