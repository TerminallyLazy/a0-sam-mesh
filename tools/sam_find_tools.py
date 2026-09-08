"""Native sam_find_tools entry point."""
from helpers.tool import Tool, Response
from usr.plugins.sam_mesh.helpers.tool_runtime import execute_native, before_native


class SamFindTools(Tool):
    async def before_execution(self, **kwargs):
        await before_native(self)

    async def execute(self, **kwargs):
        message = await execute_native(self, 'sam_find_tools', kwargs)
        return Response(message=message, break_loop=False)
