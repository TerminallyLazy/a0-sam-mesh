#!/usr/bin/env python3
"""Supervise UI ingress and Agent Zero inside the nano-init namespace."""

import asyncio
import os
import signal
import socket
import sys
from pathlib import Path


async def main():
    if set(name for _, name in socket.if_nameindex()) != {"lo", "tun0"}:
        raise SystemExit("Agent Zero refuses a namespace without exactly lo and tun0")
    if Path("/run/sam-node").exists() or os.environ.get("SAM_API_TOKEN"):
        raise SystemExit("Agent Zero refuses node authority")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    bridge = await asyncio.create_subprocess_exec(
        sys.executable,
        str(Path(__file__).with_name("ui-bridge.py")),
        "sandbox",
        "--port",
        os.environ.get("A0_WEBUI_PORT", "80"),
    )
    child = await asyncio.create_subprocess_exec(*sys.argv[1:], start_new_session=True)
    tasks = [
        asyncio.create_task(child.wait()),
        asyncio.create_task(bridge.wait()),
        asyncio.create_task(stop.wait()),
    ]
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in tasks:
        task.cancel()
    for process in (child, bridge):
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 5)
            except TimeoutError:
                process.kill()
                await process.wait()
    return child.returncode or bridge.returncode or 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
