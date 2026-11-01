from __future__ import annotations

from app.config import Settings
from .base import Backend, RawResult, derive_status


def build_backend(settings: Settings) -> Backend:
    if settings.backend == "docker":
        from .docker_backend import DockerBackend
        return DockerBackend(settings)
    if settings.backend == "process":
        from .process_backend import ProcessBackend
        return ProcessBackend(settings)
    raise ValueError(f"Unknown SANDBOX_BACKEND '{settings.backend}' (use 'docker' or 'process')")


__all__ = ["Backend", "RawResult", "derive_status", "build_backend"]
