"""Protected SAM inference profile endpoint."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class InferenceProfile(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("inference_profile", input, request)
