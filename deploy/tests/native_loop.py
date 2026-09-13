"""Native message-loop smoke with deterministic model output, no model credentials."""

import asyncio
import json
from pathlib import Path

from helpers import plugins, runtime


async def main():
    runtime.initialize()
    from agent import AgentConfig, AgentContext, UserMessage
    from helpers.llm_result import LLMResult
    from tools.response import ResponseTool

    memory = plugins.get_default_plugin_config("_memory")
    memory.update(memory_recall_enabled=False, memory_memorize_enabled=False)
    plugins.save_plugin_config("_memory", "", "", memory)
    context = AgentContext(config=AgentConfig(mcp_servers=""))
    calls = []
    observed = []

    async def fixed_model(*args, **kwargs):
        calls.append(len(kwargs.get("messages", [])))
        return LLMResult(
            response=json.dumps(
                {"tool_name": "response", "tool_args": {"text": "native-sovereign-loop-ok"}}
            ),
            mode="chat",
            state="local",
        )

    context.agent0.call_chat_model_turn = fixed_model
    original = ResponseTool.execute

    async def record(self, **kwargs):
        result = await original(self, **kwargs)
        observed.append(result.break_loop)
        return result

    ResponseTool.execute = record
    try:
        task = context.communicate(
            UserMessage("Return native-sovereign-loop-ok using the response tool.")
        )
        result = await task.result(timeout=90)
        assert result == "native-sovereign-loop-ok", repr(result)
        assert observed == [True] and len(calls) == 1 and calls[0] > 0, (observed, calls)
        assert all(
            Path("/a0/knowledge", name).is_dir() for name in ("main", "fragments", "solutions")
        )
        print(
            json.dumps(
                {
                    "native_a0_message_loop": True,
                    "model_fixture": True,
                    "response_break_loop": True,
                    "model_calls": len(calls),
                }
            )
        )
    finally:
        ResponseTool.execute = original
        context.reset()
        AgentContext.remove(context.id)


asyncio.run(main())
