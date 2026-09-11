"""Native sam_find_tools entry point."""

from helpers.tool import Response, Tool
from usr.plugins.sam_mesh.helpers.tool_runtime import before_native, execute_native


class SamFindTools(Tool):
    async def before_execution(self, **kwargs):
        await before_native(self)

    async def execute(self, **kwargs):
        message = await execute_native(self, "sam_find_tools", kwargs)
        return Response(message=message, break_loop=False)
