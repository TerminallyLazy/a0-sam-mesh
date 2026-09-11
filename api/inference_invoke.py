"""Protected SAM inference invoke endpoint."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class InferenceInvoke(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("inference_invoke", input, request)
