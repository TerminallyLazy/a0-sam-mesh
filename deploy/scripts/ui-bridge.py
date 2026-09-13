#!/usr/bin/env python3
"""Bounded stream forwarding to one fixed destination; HTTP/WebSocket transparent."""

import argparse
import asyncio
import os
import signal
import stat
from pathlib import Path


async def main(args):
    stop = asyncio.Event()
    active = set()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    async def accept(reader, writer):
        task = asyncio.current_task()
        if len(active) >= 64:
            writer.close()
            return
        active.add(task)
        upstream = None
        try:
            async with asyncio.timeout(5):
                if args.mode == "sandbox":
                    other, upstream = await asyncio.open_connection("127.0.0.1", args.port)
                else:
                    other, upstream = await asyncio.open_unix_connection(args.socket)

            async def copy(r, w):
                while chunk := await r.read(65536):
                    w.write(chunk)
                    await w.drain()

            tasks = [
                asyncio.create_task(copy(reader, upstream)),
                asyncio.create_task(copy(other, writer)),
            ]
            try:
                await asyncio.wait(tasks, timeout=3600, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for child in tasks:
                    child.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        except (OSError, TimeoutError):
            pass
        finally:
            writer.close()
            if upstream:
                upstream.close()
            active.discard(task)

    if args.mode == "sandbox":
        path = Path(args.socket)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        if path.exists():
            if not stat.S_ISSOCK(path.lstat().st_mode):
                raise ValueError("refusing to replace a non-socket")
            path.unlink()
        server = await asyncio.start_unix_server(accept, path=path)
        os.chmod(path, 0o600)
    else:
        server = await asyncio.start_server(accept, "0.0.0.0", args.port)
    try:
        await stop.wait()
    finally:
        server.close()
        for task in list(active):
            task.cancel()
        await asyncio.gather(*active, return_exceptions=True)
        await asyncio.wait_for(server.wait_closed(), 2)
    if args.mode == "sandbox":
        Path(args.socket).unlink(missing_ok=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["sandbox", "gateway"])
    p.add_argument("--socket", default="/run/a0-ui/ui.sock")
    p.add_argument("--port", type=int, required=True)
    asyncio.run(main(p.parse_args()))
