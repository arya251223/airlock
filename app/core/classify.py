"""Turn raw execution facts into the human-meaningful "which limit tripped" list.

These are *observations* derived from exit status and output text. They power
the explanation layer in the UI and are never used for security decisions.
"""
from __future__ import annotations

from typing import List

_NET_MARKERS = (
    "network is unreachable", "temporary failure in name resolution",
    "name or service not known", "no route to host", "network is down",
    "nodename nor servname", "gaierror", "errno 101",
)
_PID_MARKERS = ("resource temporarily unavailable", "blockingioerror",
                "can't start new thread", "errno 11")
_FS_MARKERS = ("read-only file system", "permission denied", "operation not permitted")


def tripped_limits(status: str, stderr: str, stdout: str, truncated: bool, policy_verdict: str) -> List[str]:
    low = (stderr or "").lower()
    out = (stdout or "").lower()
    hit: List[str] = []
    if policy_verdict == "blocked":
        hit.append("policy")
    if status == "timeout":
        hit.append("time")
    if status == "oom_killed" or "memoryerror" in low:
        hit.append("memory")
    if any(m in low for m in _NET_MARKERS) or "network blocked" in out:
        hit.append("network")
    if any(m in low for m in _PID_MARKERS) or "fork blocked" in out:
        hit.append("processes")
    if any(m in low for m in _FS_MARKERS) or "write blocked" in out:
        hit.append("filesystem")
    if truncated:
        hit.append("output")
    seen = set()
    return [h for h in hit if not (h in seen or seen.add(h))]
