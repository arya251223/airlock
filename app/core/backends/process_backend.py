"""Development / CI backend: no Docker required (Linux only).

NOT a production boundary. It exists so the whole stack can be developed and
tested on a machine without a Docker daemon, and so the test-suite can exercise
real kernel limits. It applies, from a tiny *launcher* process that then
``exec``s the interpreter (no ``preexec_fn``, so it is safe inside a threaded
web server):

  * RLIMIT_AS     memory cap        * RLIMIT_CPU   CPU-seconds cap
  * RLIMIT_FSIZE  output/file cap   * RLIMIT_NOFILE, RLIMIT_CORE=0
  * new network namespace (unshare) when the kernel/privileges allow
  * drop to uid/gid 65534 + RLIMIT_NPROC when started as root
  * scrubbed environment, throw-away read-only working directory
  * wall-clock timeout + SIGKILL of the whole process group

What it can NOT do (and ``capabilities()`` says so honestly): filesystem
isolation (the process still sees the host's world-readable files), and
RLIMIT_NPROC is per-UID so it is only enforced when we run as root and drop
to the dedicated unprivileged uid.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Optional

from app.config import Settings
from .base import Backend, RawResult, truncate_bytes

NOBODY = 65534


def _workdir_root() -> Optional[str]:
    """Scratch location for the script. Must NOT be /tmp: the sandbox gets its own tmpfs there."""
    root = os.getenv("AIRLOCK_WORKDIR_ROOT", "/var/tmp")
    return root if os.path.isdir(root) else None

LAUNCHER = r"""
import ctypes, json, os, resource, sys
cfg = json.loads(sys.argv[1]); script = sys.argv[2]
libc = ctypes.CDLL(None, use_errno=True)
CLONE_NEWNS, CLONE_NEWUSER, CLONE_NEWNET = 0x00020000, 0x10000000, 0x40000000
MS_NOSUID, MS_NODEV, MS_NOEXEC, MS_REC, MS_PRIVATE = 0x2, 0x4, 0x8, 0x4000, 0x40000
root = os.geteuid() == 0
if cfg["isolate_net"]:
    libc.unshare(CLONE_NEWNET if root else (CLONE_NEWUSER | CLONE_NEWNET))   # best effort
if cfg["private_tmp"]:
    # Private mount namespace + tmpfs on /tmp so runs cannot leave files for each other
    # or touch the host's /tmp. The mount tree is made private FIRST so nothing propagates.
    flags = CLONE_NEWNS if root else (CLONE_NEWUSER | CLONE_NEWNS)
    if libc.unshare(flags) == 0 and libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None) == 0:
        libc.mount(b"tmpfs", b"/tmp", b"tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                   ("size=%dm,mode=1777" % cfg["tmpfs_mb"]).encode())
def lim(which, soft, hard=None):
    try: resource.setrlimit(which, (soft, soft if hard is None else hard))
    except (ValueError, OSError): pass
lim(resource.RLIMIT_AS, cfg["mem_bytes"])
lim(resource.RLIMIT_CPU, cfg["cpu_seconds"], cfg["cpu_seconds"] + 1)
lim(resource.RLIMIT_FSIZE, cfg["fsize_bytes"])
lim(resource.RLIMIT_NOFILE, 64)
lim(resource.RLIMIT_CORE, 0)
if cfg["drop_privileges"]:
    lim(resource.RLIMIT_NPROC, cfg["nproc"])
    os.setgroups([]); os.setgid(cfg["uid"]); os.setuid(cfg["uid"])
os.execv(sys.executable, [sys.executable, "-I", "-u", "-B", script])
"""


class ProcessBackend(Backend):
    name = "process"

    def __init__(self, settings: Settings):
        self.s = settings
        self._caps: Optional[dict] = None
        self._is_root = hasattr(os, "geteuid") and os.geteuid() == 0

    # ------------------------------------------------------------------ core
    def _spawn(self, workdir: str, script: str, timeout_s: int, stdout_f, stderr_f) -> subprocess.Popen:
        cfg = {
            "isolate_net": True,
            "private_tmp": True,
            "tmpfs_mb": self.s.tmpfs_mb,
            "mem_bytes": self.s.memory_mb * 1024 * 1024,
            "cpu_seconds": timeout_s + 1,
            "fsize_bytes": self.s.max_output_bytes + 4096,
            "drop_privileges": self._is_root,
            "uid": NOBODY,
            "nproc": self.s.pids_limit,
        }
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONIOENCODING": "utf-8", "HOME": workdir}
        return subprocess.Popen(
            [sys.executable, "-I", "-c", LAUNCHER, json.dumps(cfg), script],
            stdin=subprocess.DEVNULL, stdout=stdout_f, stderr=stderr_f,
            cwd=workdir, env=env, start_new_session=True, close_fds=True,
        )

    def run(self, code: str, timeout_s: int) -> RawResult:
        res = RawResult()
        t0 = time.perf_counter()
        workdir = tempfile.mkdtemp(prefix="airlock-", dir=_workdir_root())
        try:
            os.chmod(workdir, 0o755)
            script = os.path.join(workdir, "main.py")
            with open(script, "w", encoding="utf-8") as fh:
                fh.write(code)
            os.chmod(script, 0o644)
            out_path, err_path = os.path.join(workdir, ".stdout"), os.path.join(workdir, ".stderr")
            # The open fds are inherited, so the unprivileged child can write to them
            # even though the files are owned by us.
            with open(out_path, "wb") as fo, open(err_path, "wb") as fe:
                os.chmod(workdir, 0o555)            # read-only cwd for the sandboxed code
                t_prep = time.perf_counter()
                proc = self._spawn(workdir, script, timeout_s, fo, fe)
                try:
                    exit_code = proc.wait(timeout=timeout_s)
                except subprocess.TimeoutExpired:
                    res.timed_out = True
                    exit_code = 124
                    self._kill_group(proc)
                else:
                    self._kill_group(proc)          # reap stragglers (forked children)
                t_run = time.perf_counter()
            os.chmod(workdir, 0o755)
            res.exit_code = exit_code if exit_code >= 0 else 128 + (-exit_code)
            limit = self.s.max_output_bytes
            with open(out_path, "rb") as fo:
                res.stdout, cut_o = truncate_bytes(fo.read(limit + 1), limit)
            with open(err_path, "rb") as fe:
                res.stderr, cut_e = truncate_bytes(fe.read(limit + 1), limit)
            res.truncated = cut_o or cut_e
            res.phases = {"prepare_ms": round((t_prep - t0) * 1000, 1),
                          "run_ms": round((t_run - t_prep) * 1000, 1)}
        finally:
            t_clean = time.perf_counter()
            try:
                os.chmod(workdir, 0o755)
            except OSError:
                pass
            shutil.rmtree(workdir, ignore_errors=True)
            res.phases["cleanup_ms"] = round((time.perf_counter() - t_clean) * 1000, 1)
        return res

    @staticmethod
    def _group_members(pgid: int) -> int:
        """Count live *and zombie* processes in a process group by scanning /proc."""
        n = 0
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/stat") as fh:
                    stat = fh.read()
            except OSError:
                continue
            # format: pid (comm) state ppid pgrp ...  (comm may contain spaces/parens)
            fields = stat[stat.rindex(")") + 2:].split()
            if int(fields[2]) == pgid:
                n += 1
        return n

    def _kill_group(self, proc: subprocess.Popen) -> None:
        """SIGKILL the whole group, then wait until nothing of it is left.

        Waiting matters: zombie children keep counting against the per-UID RLIMIT_NPROC
        until init reaps them, which would make the *next* run fail spuriously.
        """
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and self._group_members(proc.pid) > 0:
            time.sleep(0.02)

    # ------------------------------------------------------------------ info
    def capabilities(self) -> dict:
        if self._caps is None:
            net_isolated = private_tmp = False
            try:
                net_isolated, private_tmp = self._probe()
            except Exception:  # noqa: BLE001
                pass
            self._caps = {
                "isolation": "process (dev only)",
                "network_isolated": net_isolated,
                "memory_limited": True,
                "cpu_limited": True,        # CPU-seconds cap, not a share
                "pids_limited": self._is_root,
                "readonly_rootfs": False,
                "fresh_tmp_per_run": private_tmp,
                "non_root": self._is_root,
            }
        return self._caps

    def _probe(self) -> tuple[bool, bool]:
        # /proc/self/net/dev is per-task (reflects the *current* network namespace);
        # /sys/class/net is not, because sysfs is bound to the mount-time namespace.
        probe_code = (
            "ifs = [l.split(':')[0].strip() for l in open('/proc/self/net/dev').readlines()[2:]]\n"
            "tmp = any(' /tmp ' in l and ' tmpfs ' in l for l in open('/proc/self/mountinfo'))\n"
            "print(','.join(sorted(ifs)), tmp)"
        )
        out = self.run(probe_code, 5).stdout.strip().split()
        return out[0] == "lo", out[1] == "True"

    def healthcheck(self) -> dict:
        if not sys.platform.startswith("linux"):
            return {"ok": False, "detail": "process backend requires Linux"}
        caps = self.capabilities()
        gaps = [k for k in ("network_isolated", "pids_limited", "fresh_tmp_per_run") if not caps[k]]
        detail = "DEV-ONLY backend (not a production boundary)"
        if gaps:
            detail += "; not enforced here: " + ", ".join(gaps)
        return {"ok": True, "detail": detail}
