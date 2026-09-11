from helpers.extension import Extension
from usr.plugins.sam_mesh.helpers.decisions import DecisionError


class EmbassyToolBoundary(Extension):
    async def execute(self, tool_name="", **kwargs):
        if not self.agent:
            return
        policy = self.agent.context.get_data("sam_embassy_tool_policy")
        if policy is None:
            return
        from helpers.projects import get_context_project_name

        scope = self.agent.context.get_data("sam_embassy_scope")
        if (
            scope != [get_context_project_name(self.agent.context), self.agent.config.profile]
            or tool_name not in policy
        ):
            raise DecisionError("embassy_tool_denied")
