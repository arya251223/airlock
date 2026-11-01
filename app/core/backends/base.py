from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class RawResult:
    """What a backend reports after running one script."""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    timed_out: bool = False
    oom_killed: bool = False
    truncated: bool = False
    # millisecond timings of the container lifecycle phases
    phases: Dict[str, float] = field(default_factory=dict)


def derive_status(r: RawResult) -> str:
    if r.timed_out:
        return "timeout"
    if r.oom_killed:
        return "oom_killed"
    if r.truncated and r.exit_code != 0:
        return "output_limit"
    return "success" if r.exit_code == 0 else "error"


def truncate_bytes(data: bytes, limit: int) -> tuple[str, bool]:
    """Decode ``data`` safely, cutting at ``limit`` bytes. Returns (text, was_truncated)."""
    cut = len(data) > limit
    text = data[:limit].decode("utf-8", errors="replace")
    if cut:
        text += f"\n…[output truncated at {limit // 1024} KB]"
    return text, cut


class Backend(ABC):
    name: str = "abstract"

    @abstractmethod
    def run(self, code: str, timeout_s: int) -> RawResult:
        """Execute ``code`` in isolation. Must never raise for user-code failures."""

    @abstractmethod
    def capabilities(self) -> dict:
        """Describe which isolation guarantees this backend actually provides."""

    @abstractmethod
    def healthcheck(self) -> dict:
        """Return {"ok": bool, "detail": str}."""
