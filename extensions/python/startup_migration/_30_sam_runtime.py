from helpers.extension import Extension
from helpers.plugins import call_plugin_hook


class SamRuntime(Extension):
    def execute(self, **kwargs):
        call_plugin_hook("sam_mesh", "ensure_runtime")
