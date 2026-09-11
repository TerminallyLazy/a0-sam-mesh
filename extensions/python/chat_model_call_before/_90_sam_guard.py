from helpers.extension import Extension
from usr.plugins.sam_mesh.helpers.inference import guard_native_model


class SamModelGuard(Extension):
    async def execute(self, call_data, **kwargs):
        call_data["model"] = guard_native_model(self.agent, call_data["model"])
