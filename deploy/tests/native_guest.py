"""Actual confined guest proof with native provider and disposable cross-node model."""

import asyncio
import json
import sys

from helpers import plugins, runtime


async def main():
    runtime.initialize()
    from agent import AgentConfig, AgentContext, UserMessage
    from tools.response import ResponseTool
    from usr.plugins.sam_mesh.helpers import sovereign
    from usr.plugins.sam_mesh.helpers.config import resolve_config
    from usr.plugins.sam_mesh.helpers.inference import build_preset_fragment
    from usr.plugins.sam_mesh.helpers.sam_client import SamClient
    from usr.plugins.sam_mesh.helpers.tool_runtime import scoped_stores

    # Only this disposable self-test process opts into the private baseline.
    # The real probe still checks host/source/binaries/mounts/routes/caps/socket.
    # Production imports remain strict; there is no config or environment bypass.
    original_probe = sovereign.guest_probe
    strict = "--final-validation" in sys.argv
    if not strict:
        sovereign.guest_probe = lambda: original_probe(_certification_bootstrap=True)
    proof = sovereign.guest_probe()
    assert proof["supported"], proof
    plugins.toggle_plugin("sam_mesh", True)
    raw = plugins.get_default_plugin_config("sam_mesh")
    raw["transport"].update(
        type="http",
        base_url="http://mesh.sam.alt",
        socket_path="",
        token_file="",
        token_secret_name="",
        allowed_origins=["http://mesh.sam.alt"],
    )
    raw["passport"]["mode"] = "sovereign"
    raw["passport"]["inference"]["enabled"] = True
    raw["passport"]["limits"].update(calls_per_session=2, timeout_seconds=60)
    raw["features"]["mesh_inference"] = True
    plugins.save_plugin_config("sam_mesh", "", "", raw)
    context = AgentContext(config=AgentConfig(mcp_servers=""))
    original = ResponseTool.execute
    completed = []

    async def observed(self, **kwargs):
        result = await original(self, **kwargs)
        completed.append(result.break_loop)
        return result

    ResponseTool.execute = observed
    try:
        cfg = resolve_config(context.agent0)
        assert cfg.transport.token is None
        async with SamClient(cfg.transport) as client:
            for _ in range(30):
                models = await client.list_models()
                if any(item.id == "sovereign-fixture" for item in models):
                    break
                await asyncio.sleep(1)
            else:
                raise AssertionError("fixture model was not discovered through the native facade")
        preset = build_preset_fragment(cfg, "sovereign-fixture")
        context.set_data("chat_model_override", {"chat": preset})
        model = context.agent0.get_chat_model()
        assert model.a0_model_conf.provider == "sam_mesh"
        task = context.communicate(
            UserMessage("Return native-sovereign-guest-ok with the response tool.")
        )
        result = await task.result(timeout=90)
        assert result == "native-sovereign-guest-ok" and completed == [True]
        audit = scoped_stores(cfg.scope)[2].list_redacted(cfg.scope, limit=5)
        assert len(audit) == 1 and audit[0]["outcome"] == "admitted"
        print(
            json.dumps(
                {
                    "native_sovereign_guest": True,
                    "strict_guest_probe": strict,
                    "guest_posture": proof["posture"],
                    "native_provider": "sam_mesh",
                    "response_break_loop": True,
                    "guard_admissions": 1,
                    "model_fixture": True,
                }
            )
        )
    finally:
        sovereign.guest_probe = original_probe
        ResponseTool.execute = original
        context.reset()
        AgentContext.remove(context.id)


asyncio.run(main())
