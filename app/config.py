"""Central configuration. Every limit is overridable through environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int) -> int:
    return int(os.getenv(name, default))


def _float(name: str, default: float) -> float:
    return float(os.getenv(name, default))


@dataclass(frozen=True)
class Settings:
    # --- backend selection -------------------------------------------------
    backend: str = "docker"             # "docker" (production) | "process" (dev only)
    policy_mode: str = "warn"           # "off" | "warn" | "block"

    # --- per-execution resource limits -------------------------------------
    memory_mb: int = 128
    cpus: float = 0.5
    pids_limit: int = 64
    tmpfs_mb: int = 16
    max_output_bytes: int = 64 * 1024   # stdout / stderr are each truncated here
    default_timeout_s: int = 5
    max_timeout_s: int = 15
    max_code_chars: int = 20_000

    # --- docker backend ----------------------------------------------------
    docker_image: str = "airlock-runner:latest"
    docker_runtime: str = ""            # e.g. "runsc" to use gVisor

    # --- service protections -----------------------------------------------
    max_concurrent: int = 4             # simultaneous sandboxes
    rate_limit_per_min: int = 30        # per client IP
    api_key: str = ""                   # if set, X-API-Key header is required

    history_size: int = 200

    @classmethod
    def from_env(cls) -> "Settings":
        d = cls()
        return cls(
            backend=os.getenv("SANDBOX_BACKEND", d.backend).lower(),
            policy_mode=os.getenv("SANDBOX_POLICY", d.policy_mode).lower(),
            memory_mb=_int("SANDBOX_MEMORY_MB", d.memory_mb),
            cpus=_float("SANDBOX_CPUS", d.cpus),
            pids_limit=_int("SANDBOX_PIDS_LIMIT", d.pids_limit),
            tmpfs_mb=_int("SANDBOX_TMPFS_MB", d.tmpfs_mb),
            max_output_bytes=_int("SANDBOX_MAX_OUTPUT_BYTES", d.max_output_bytes),
            default_timeout_s=_int("SANDBOX_DEFAULT_TIMEOUT", d.default_timeout_s),
            max_timeout_s=_int("SANDBOX_MAX_TIMEOUT", d.max_timeout_s),
            max_code_chars=_int("SANDBOX_MAX_CODE_CHARS", d.max_code_chars),
            docker_image=os.getenv("SANDBOX_IMAGE", d.docker_image),
            docker_runtime=os.getenv("SANDBOX_DOCKER_RUNTIME", d.docker_runtime),
            max_concurrent=_int("SANDBOX_MAX_CONCURRENT", d.max_concurrent),
            rate_limit_per_min=_int("SANDBOX_RATE_LIMIT_PER_MIN", d.rate_limit_per_min),
            api_key=os.getenv("SANDBOX_API_KEY", d.api_key),
            history_size=_int("SANDBOX_HISTORY_SIZE", d.history_size),
        )

    def public_limits(self) -> dict:
        """The subset of limits the UI is allowed to display."""
        return {
            "memory_mb": self.memory_mb,
            "cpus": self.cpus,
            "pids_limit": self.pids_limit,
            "max_output_bytes": self.max_output_bytes,
            "default_timeout_s": self.default_timeout_s,
            "max_timeout_s": self.max_timeout_s,
            "max_code_chars": self.max_code_chars,
        }
