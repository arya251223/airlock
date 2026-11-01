"""Production backend: one throw-away, locked-down Docker container per execution.

Hardening applied to every container (see ``_create_kwargs``):

  * network_mode="none"          -> no network interfaces except loopback
  * mem_limit == memswap_limit   -> hard RAM cap, swap disabled
  * nano_cpus                    -> CPU share cap (0.5 core by default)
  * pids_limit                   -> fork-bomb protection
  * read_only rootfs + tmpfs     -> only a small, noexec scratch dir is writable
  * cap_drop=ALL, no-new-privileges, non-root user 65534
  * json-file log driver capped  -> output flood cannot fill the host disk
  * wall-clock timeout enforced by us, container killed then force-removed
  * optional alternative OCI runtime (e.g. gVisor "runsc") via SANDBOX_DOCKER_RUNTIME

The user's code is delivered through an environment variable (base64) rather
than a bind-mounted file. That avoids host-path/permission problems, works when
the Docker daemon is remote, and is compatible with a read-only rootfs.
"""
from __future__ import annotations

import base64
import importlib
import time
from typing import Any, Optional

from app.config import Settings
from .base import Backend, RawResult, truncate_bytes

# Executed inside the container. Pops the env var so the script cannot trivially
# re-read it, then compiles with a friendly filename for tracebacks.
BOOTSTRAP = (
    "import base64, os\n"
    "src = base64.b64decode(os.environ.pop('SANDBOX_CODE')).decode('utf-8')\n"
    "g = {'__name__': '__main__', '__file__': 'main.py'}\n"
    "exec(compile(src, 'main.py', 'exec'), g)\n"
)


class DockerBackend(Backend):
    name = "docker"

    def __init__(self, settings: Settings, client: Optional[Any] = None, docker_module: Optional[Any] = None):
        self.s = settings
        self._client = client
        self._docker = docker_module

    # -- lazy imports so the app can start (and report health) without Docker --
    @property
    def docker(self):
        if self._docker is None:
            self._docker = importlib.import_module("docker")
        return self._docker

    @property
    def client(self):
        if self._client is None:
            self._client = self.docker.from_env()
        return self._client

    # ------------------------------------------------------------------ info
    def capabilities(self) -> dict:
        return {
            "isolation": "container" + (f" ({self.s.docker_runtime})" if self.s.docker_runtime else ""),
            "network_isolated": True,
            "memory_limited": True,
            "cpu_limited": True,
            "pids_limited": True,
            "readonly_rootfs": True,
            "non_root": True,
        }

    def healthcheck(self) -> dict:
        try:
            self.client.ping()
        except Exception as exc:  # noqa: BLE001 - report any connectivity problem
            return {"ok": False, "detail": f"Docker daemon unreachable: {exc}"}
        try:
            self.client.images.get(self.s.docker_image)
        except Exception:  # noqa: BLE001
            return {
                "ok": False,
                "detail": f"Runner image '{self.s.docker_image}' not found. "
                          f"Build it: docker build -f docker/runner.Dockerfile -t {self.s.docker_image} .",
            }
        return {"ok": True, "detail": f"Docker reachable, image {self.s.docker_image} present"}

    # ------------------------------------------------------------- execution
    def _create_kwargs(self, encoded_code: str) -> dict:
        d = self.docker
        s = self.s
        mem = f"{s.memory_mb}m"
        kwargs = dict(
            image=s.docker_image,
            command=["python", "-I", "-u", "-c", BOOTSTRAP],
            environment={
                "SANDBOX_CODE": encoded_code,
                "PYTHONUNBUFFERED": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            network_mode="none",
            mem_limit=mem,
            memswap_limit=mem,                       # == mem_limit -> no swap
            nano_cpus=int(s.cpus * 1_000_000_000),
            pids_limit=s.pids_limit,
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            user="65534:65534",
            working_dir="/tmp",
            tmpfs={"/tmp": f"rw,noexec,nosuid,nodev,size={s.tmpfs_mb}m"},
            ulimits=[d.types.Ulimit(name="nofile", soft=64, hard=64),
                     d.types.Ulimit(name="core", soft=0, hard=0)],
            log_config=d.types.LogConfig(type=d.types.LogConfig.types.JSON,
                                         config={"max-size": "1m", "max-file": "1"}),
            labels={"app": "airlock", "role": "ephemeral-runner"},
            init=True,
        )
        if s.docker_runtime:
            kwargs["runtime"] = s.docker_runtime
        return kwargs

    def run(self, code: str, timeout_s: int) -> RawResult:
        result = RawResult()
        container = None
        t0 = time.perf_counter()
        try:
            encoded = base64.b64encode(code.encode("utf-8")).decode("ascii")
            container = self.client.containers.create(**self._create_kwargs(encoded))
            t_created = time.perf_counter()

            container.start()
            timed_out = False
            exit_code = -1
            try:
                wait = container.wait(timeout=timeout_s)
                exit_code = int(wait.get("StatusCode", -1))
            except Exception:  # noqa: BLE001
                # docker-py surfaces a client-side read timeout as requests' ReadTimeout /
                # ConnectionError depending on urllib3 version. Elapsed time is the
                # version-independent discriminator.
                if time.perf_counter() - t_created >= timeout_s - 0.05:
                    timed_out = True
                else:
                    raise
            if timed_out:
                try:
                    container.kill()
                except Exception:  # noqa: BLE001 - already exited is fine
                    pass
                exit_code = 124
            t_ran = time.perf_counter()

            oom = False
            try:
                container.reload()
                state = container.attrs.get("State", {})
                oom = bool(state.get("OOMKilled"))
                if not timed_out:
                    exit_code = int(state.get("ExitCode", exit_code))
            except Exception:  # noqa: BLE001
                pass

            limit = self.s.max_output_bytes
            out, cut_o = truncate_bytes(container.logs(stdout=True, stderr=False) or b"", limit)
            err, cut_e = truncate_bytes(container.logs(stdout=False, stderr=True) or b"", limit)

            result.stdout, result.stderr = out, err
            result.exit_code = exit_code
            result.timed_out = timed_out
            result.oom_killed = oom
            result.truncated = cut_o or cut_e
            result.phases = {
                "prepare_ms": round((t_created - t0) * 1000, 1),
                "run_ms": round((t_ran - t_created) * 1000, 1),
            }
        finally:
            t_clean = time.perf_counter()
            if container is not None:
                try:
                    container.remove(force=True, v=True)
                except Exception:  # noqa: BLE001
                    pass
            result.phases["cleanup_ms"] = round((time.perf_counter() - t_clean) * 1000, 1)
        return result
