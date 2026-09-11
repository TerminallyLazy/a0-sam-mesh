"""Local control-plane budgets excluding SAM network discovery."""

import statistics
import time
from datetime import timedelta

from tests.test_gate import GateTests


class PerformanceTests(GateTests):
    async def test_preflight_p95_and_offline_emergency(self):
        samples = []
        for _ in range(200):
            self.now += timedelta(seconds=3)
            start = time.perf_counter()
            await self.preflight()
            samples.append(time.perf_counter() - start)
        p95 = statistics.quantiles(samples, n=100)[94]
        self.assertLess(p95, 0.150)
        start = time.perf_counter()
        from helpers.control import stop_scope

        stop_scope(self.config.scope, (self.store, self.leases, self.audit))
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 0.500)
        print(f"PREFLIGHT_P95_MS={p95 * 1000:.3f}; OFFLINE_STOP_MS={elapsed * 1000:.3f}")
