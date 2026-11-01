"""Framework-independent orchestration layer.

Keeping this free of FastAPI means the whole pipeline (policy check, admission
control, execution, classification, statistics) is unit-testable without a web
server, and the HTTP layer stays a thin adapter.
"""
from __future__ import annotations

import statistics
import threading
import time
import uuid
from collections import Counter, deque
from typing import Deque, Dict, Optional

from app.config import Settings
from app.core import policy as policy_mod
from app.core.backends import Backend, build_backend, derive_status
from app.core.classify import tripped_limits


class Busy(Exception):
    """All sandbox slots are in use."""


class RateLimited(Exception):
    def __init__(self, retry_after: float):
        super().__init__("rate limit exceeded")
        self.retry_after = retry_after


class TokenBucket:
    """Per-client token bucket. capacity == per-minute allowance."""

    def __init__(self, per_minute: int, clock=time.monotonic):
        self.capacity = max(1, per_minute)
        self.rate = self.capacity / 60.0
        self._clock = clock
        self._state: Dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def take(self, client: str) -> Optional[float]:
        """Return None if allowed, otherwise seconds until a token is available."""
        now = self._clock()
        with self._lock:
            tokens, last = self._state.get(client, (float(self.capacity), now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens >= 1.0:
                self._state[client] = (tokens - 1.0, now)
                return None
            self._state[client] = (tokens, now)
            return (1.0 - tokens) / self.rate


class Stats:
    def __init__(self, history: int):
        self._lock = threading.Lock()
        self.started = time.time()
        self.total = 0
        self.by_status: Counter = Counter()
        self.tripped: Counter = Counter()
        self._durations: Deque[float] = deque(maxlen=history)
        self.recent: Deque[dict] = deque(maxlen=25)
        self.in_flight = 0

    def begin(self) -> None:
        with self._lock:
            self.in_flight += 1

    def end(self) -> None:
        with self._lock:
            self.in_flight -= 1

    def record(self, rid: str, status: str, ms: float, tripped: list, code_len: int) -> None:
        with self._lock:
            self.total += 1
            self.by_status[status] += 1
            self.tripped.update(tripped)
            self._durations.append(ms)
            self.recent.appendleft({"id": rid, "status": status, "ms": ms,
                                    "tripped": tripped, "code_chars": code_len, "at": time.time()})

    def snapshot(self) -> dict:
        with self._lock:
            d = sorted(self._durations)

            def pct(p: float) -> float:
                return round(d[min(len(d) - 1, int(len(d) * p))], 1) if d else 0.0

            return {
                "uptime_s": round(time.time() - self.started, 1),
                "total_executions": self.total,
                "in_flight": self.in_flight,
                "by_status": dict(self.by_status),
                "limits_tripped": dict(self.tripped),
                "latency_ms": {"p50": pct(0.50), "p95": pct(0.95),
                               "mean": round(statistics.fmean(d), 1) if d else 0.0},
                "recent": list(self.recent),
            }


class SandboxService:
    def __init__(self, settings: Settings, backend: Optional[Backend] = None, clock=time.monotonic):
        self.s = settings
        self.backend = backend or build_backend(settings)
        self._slots = threading.BoundedSemaphore(settings.max_concurrent)
        self._bucket = TokenBucket(settings.rate_limit_per_min, clock)
        self.stats = Stats(settings.history_size)

    # ------------------------------------------------------------------ API
    def execute(self, code: str, timeout_s: Optional[int] = None, client: str = "local") -> dict:
        timeout = min(max(1, timeout_s or self.s.default_timeout_s), self.s.max_timeout_s)
        rid = uuid.uuid4().hex[:12]

        wait = self._bucket.take(client)
        if wait is not None:
            raise RateLimited(wait)

        t_policy = time.perf_counter()
        report = policy_mod.analyze(code, self.s.policy_mode)
        policy_ms = round((time.perf_counter() - t_policy) * 1000, 2)

        if report.verdict == "blocked":
            msg = "Blocked by policy before execution:\n" + "\n".join(
                f"  line {f.line}: {f.message} [{f.category}]" for f in report.findings if f.severity == "high")
            out = self._response(rid, "blocked", "", msg, 126, policy_ms, False,
                                 {"policy_ms": policy_ms}, report, ["policy"])
            self.stats.record(rid, "blocked", out["execution_time_ms"], out["tripped"], len(code))
            return out

        if not self._slots.acquire(blocking=False):
            raise Busy()
        self.stats.begin()
        t0 = time.perf_counter()
        try:
            try:
                raw = self.backend.run(code, timeout)
                status = derive_status(raw)
                phases = {"policy_ms": policy_ms, **raw.phases}
                tripped = tripped_limits(status, raw.stderr, raw.stdout, raw.truncated, report.verdict)
                total_ms = round((time.perf_counter() - t0) * 1000 + policy_ms, 1)
                out = self._response(rid, status, raw.stdout, raw.stderr, raw.exit_code, total_ms,
                                     raw.truncated, phases, report, tripped)
            except Exception as exc:  # noqa: BLE001 - infrastructure failure, not user code
                total_ms = round((time.perf_counter() - t0) * 1000, 1)
                out = self._response(rid, "internal_error", "", f"Sandbox backend failure: {exc}", -1,
                                     total_ms, False, {"policy_ms": policy_ms}, report, [])
        finally:
            self.stats.end()
            self._slots.release()
        self.stats.record(rid, out["status"], out["execution_time_ms"], out["tripped"], len(code))
        return out

    def _response(self, rid, status, stdout, stderr, exit_code, ms, truncated, phases, report, tripped) -> dict:
        return {
            "id": rid, "status": status, "stdout": stdout, "stderr": stderr,
            "exit_code": exit_code, "execution_time_ms": ms, "truncated": truncated,
            "backend": self.backend.name, "tripped": tripped, "phases": phases,
            "policy": report.to_dict(),
        }

    def health(self) -> dict:
        h = self.backend.healthcheck()
        return {"ok": h["ok"], "backend": self.backend.name, "detail": h["detail"],
                "capabilities": self.backend.capabilities() if h["ok"] else {}}
