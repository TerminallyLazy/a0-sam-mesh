"""Native sam_route_preview entry point."""

from helpers.tool import Response, Tool
from usr.plugins.sam_mesh.helpers.tool_runtime import before_native, execute_native


class SamRoutePreview(Tool):
    async def before_execution(self, **kwargs):
        await before_native(self)

    async def execute(self, **kwargs):
        message = await execute_native(self, "sam_route_preview", kwargs)
        return Response(message=message, break_loop=False)
