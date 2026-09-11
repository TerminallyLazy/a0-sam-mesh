"""Protected SAM deployment status endpoint."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class DeploymentStatus(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("deployment_status", input, request)
