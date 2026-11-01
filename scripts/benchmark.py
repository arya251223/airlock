"""Latency / throughput benchmark.
   python -m scripts.benchmark            (uses SANDBOX_BACKEND, default docker)
   SANDBOX_BACKEND=process python -m scripts.benchmark
"""
import concurrent.futures as cf
import statistics
import sys
import time

from app.config import Settings
from app.service import SandboxService


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


def main() -> int:
    s = Settings.from_env()
    svc = SandboxService(Settings(**{**s.__dict__, "rate_limit_per_min": 10**6, "max_concurrent": 4}))
    h = svc.health()
    if not h["ok"]:
        print("backend unavailable:", h["detail"]); return 2
    svc.execute("print(1)", 5)  # warm-up

    N = 40
    lat = []
    for _ in range(N):
        t = time.perf_counter(); r = svc.execute("print(sum(range(1000)))", 5)
        assert r["status"] == "success", r
        lat.append((time.perf_counter() - t) * 1000)
    print(f"backend={svc.backend.name}")
    print(f"sequential x{N}: p50={pct(lat,.5):.0f} ms  p95={pct(lat,.95):.0f} ms  mean={statistics.fmean(lat):.0f} ms")

    M = 60
    t = time.perf_counter()
    with cf.ThreadPoolExecutor(4) as pool:
        res = list(pool.map(lambda _: svc.execute("print(sum(range(1000)))", 5)["status"], range(M)))
    dt = time.perf_counter() - t
    print(f"concurrent x{M} (4 slots): {M/dt:.1f} runs/s, all success={all(x=='success' for x in res)}")

    kill = []
    for _ in range(3):
        t = time.perf_counter(); r = svc.execute("while True: pass", 1)
        kill.append((time.perf_counter() - t) * 1000)
        assert r["status"] == "timeout"
    print(f"1 s timeout enforcement: wall time {min(kill):.0f}-{max(kill):.0f} ms (overshoot {min(kill)-1000:.0f}-{max(kill)-1000:.0f} ms)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
