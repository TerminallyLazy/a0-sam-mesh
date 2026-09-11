"""Explicit publication planning and withdrawal-before-stop lifecycle."""

import asyncio
from dataclasses import asdict

from .decisions import DecisionError
from .embassy_config import EmbassyService


def publication_plan(value, port=None):
    service = EmbassyService.from_dict(value)
    if port is not None and (type(port) is not int or not 1024 <= port <= 65535):
        raise DecisionError("invalid_broker_port")
    fragment = {
        "version": "v1alpha1",
        "services": [
            {
                "type": "mcp",
                "name": service.name,
                "description": service.description,
                "target_url": f"http://127.0.0.1:{port}/mcp" if port else None,
            }
        ],
    }
    return {
        "state": "closed",
        "advertised": False,
        "service": asdict(service),
        "fragment": fragment if port else None,
        "status": "unsupported",
        "blockers": ["verified_origin_transport_required", "operator_node_configuration_required"],
        "operator_action": "Review generated SAM service configuration after a local broker "
        "passes health and caller isolation. SAM has no dynamic service registration API.",
    }


class Publication:
    def __init__(self, health, advertise, withdraw, stop):
        self.health, self.advertise, self.withdraw, self.stop = health, advertise, withdraw, stop
        self.state = "closed"
        self.withdrawal_pending = False
        self.lock = asyncio.Lock()

    async def publish(self, *, acknowledgment):
        if acknowledgment != "PUBLISH":
            raise DecisionError("publication_acknowledgment_required")
        async with self.lock:
            if self.state == "published":
                return
            self.state = "starting"
            try:
                async with asyncio.timeout(10):
                    if not await self.health():
                        raise DecisionError("broker_unhealthy")
                self.state = "healthy_not_published"
                async with asyncio.timeout(30):
                    if await self.advertise():
                        self.state = "published"
            except BaseException:
                if self.state == "starting":
                    self.state = "closed"
                raise

    async def close(self):
        async with self.lock:
            self.state = "draining"
            try:
                async with asyncio.timeout(5):
                    self.withdrawal_pending = not await self.withdraw()
            except Exception:
                self.withdrawal_pending = True
            finally:
                await self.stop()
                self.state = "closed_withdrawal_pending" if self.withdrawal_pending else "closed"
