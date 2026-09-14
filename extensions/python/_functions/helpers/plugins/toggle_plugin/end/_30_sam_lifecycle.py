from helpers.extension import Extension
from helpers.plugins import call_plugin_hook


class SamLifecycle(Extension):
    def execute(self, data, **kwargs):
        args, options = data.get("args", ()), data.get("kwargs", {})
        name = options.get("plugin_name", args[0] if args else "")
        enabled = options.get("enabled", args[1] if len(args) > 1 else True)
        project = options.get("project_name", args[2] if len(args) > 2 else "")
        profile = options.get("agent_profile", args[3] if len(args) > 3 else "")
        if (
            name == "sam_mesh"
            and enabled
            and not project
            and not profile
            and data.get("exception") is None
        ):
            call_plugin_hook("sam_mesh", "ensure_runtime")
