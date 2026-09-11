"""Explicitly reopen a stopped scope without restoring prior approvals."""

from helpers.api import ApiHandler, Request
from usr.plugins.sam_mesh.helpers.control_api import process


class Resume(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return await process("resume", input, request)
