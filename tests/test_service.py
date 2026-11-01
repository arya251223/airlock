import threading
import time
import unittest

from app.config import Settings
from app.core.backends.base import Backend, RawResult
from app.service import Busy, RateLimited, SandboxService, TokenBucket


class FakeBackend(Backend):
    name = "fake"

    def __init__(self, result=None, gate=None, boom=None):
        self.result = result or RawResult(stdout="ok\n", exit_code=0, phases={"prepare_ms": 1, "run_ms": 2, "cleanup_ms": 1})
        self.gate, self.boom, self.calls = gate, boom, []

    def run(self, code, timeout_s):
        self.calls.append((code, timeout_s))
        if self.gate:
            self.gate.wait(5)
        if self.boom:
            raise self.boom
        return self.result

    def capabilities(self): return {}
    def healthcheck(self): return {"ok": True, "detail": "fake"}


def svc(backend=None, **kw):
    s = Settings(backend="process", rate_limit_per_min=kw.pop("rate", 1000), **kw)
    return SandboxService(s, backend or FakeBackend())


class ServiceTests(unittest.TestCase):
    def test_success_path_shape(self):
        out = svc().execute("print(1)", 3)
        self.assertEqual(out["status"], "success")
        self.assertEqual(out["backend"], "fake")
        self.assertIn("policy_ms", out["phases"])
        self.assertEqual(out["policy"]["verdict"], "clean")

    def test_timeout_clamped_to_max(self):
        b = FakeBackend()
        svc(b, max_timeout_s=10).execute("1", 999)
        self.assertEqual(b.calls[0][1], 10)

    def test_default_timeout_used(self):
        b = FakeBackend()
        svc(b, default_timeout_s=4).execute("1", None)
        self.assertEqual(b.calls[0][1], 4)

    def test_policy_block_never_reaches_backend(self):
        b = FakeBackend()
        out = svc(b, policy_mode="block").execute("import subprocess", 3)
        self.assertEqual(out["status"], "blocked")
        self.assertEqual(out["tripped"], ["policy"])
        self.assertEqual(b.calls, [])

    def test_backend_exception_becomes_internal_error(self):
        out = svc(FakeBackend(boom=RuntimeError("daemon down"))).execute("1", 3)
        self.assertEqual(out["status"], "internal_error")
        self.assertIn("daemon down", out["stderr"])

    def test_slot_released_after_backend_failure(self):
        s = svc(FakeBackend(boom=RuntimeError("x")), max_concurrent=1)
        s.execute("1", 1); s.execute("1", 1)  # would raise Busy if the slot leaked

    def test_busy_when_all_slots_taken(self):
        gate = threading.Event()
        s = svc(FakeBackend(gate=gate), max_concurrent=1)
        t = threading.Thread(target=s.execute, args=("1", 3)); t.start()
        time.sleep(0.15)
        with self.assertRaises(Busy):
            s.execute("2", 3)
        gate.set(); t.join()
        s.execute("3", 3)  # slot is free again

    def test_stats_counts(self):
        s = svc()
        s.execute("1", 1); s.execute("2", 1)
        snap = s.stats.snapshot()
        self.assertEqual(snap["total_executions"], 2)
        self.assertEqual(snap["by_status"]["success"], 2)
        self.assertEqual(snap["in_flight"], 0)
        self.assertEqual(len(snap["recent"]), 2)

    def test_rate_limit_per_client(self):
        s = svc(rate=2)
        s.execute("1", 1, client="a"); s.execute("1", 1, client="a")
        with self.assertRaises(RateLimited) as cm:
            s.execute("1", 1, client="a")
        self.assertGreater(cm.exception.retry_after, 0)
        s.execute("1", 1, client="b")  # other clients unaffected


class TokenBucketTests(unittest.TestCase):
    def test_refill_over_time(self):
        now = [0.0]
        b = TokenBucket(60, clock=lambda: now[0])   # 1 token / second
        for _ in range(60):
            self.assertIsNone(b.take("c"))
        self.assertIsNotNone(b.take("c"))
        now[0] += 2.0
        self.assertIsNone(b.take("c"))
        self.assertIsNone(b.take("c"))
        self.assertIsNotNone(b.take("c"))


if __name__ == "__main__":
    unittest.main()
