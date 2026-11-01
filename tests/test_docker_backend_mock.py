"""Verifies the Docker backend's *logic* against a fake Docker client.

This proves we ask Docker for the right hardening flags and handle timeouts,
OOM kills, truncation and cleanup correctly. It does NOT prove Docker itself
enforces them; run `make test-docker` on a machine with a daemon for that.
"""
import base64
import time
import types
import unittest

from app.config import Settings
from app.core.backends.base import derive_status
from app.core.backends.docker_backend import BOOTSTRAP, DockerBackend


class _LogTypes: JSON = "json-file"


def _LogConfig(type, config): return {"Type": type, "Config": config}
_LogConfig.types = _LogTypes


def _Ulimit(name, soft, hard): return {"Name": name, "Soft": soft, "Hard": hard}


FAKE_DOCKER = types.SimpleNamespace(types=types.SimpleNamespace(Ulimit=_Ulimit, LogConfig=_LogConfig))


class FakeContainer:
    def __init__(self, behavior):
        self.b = behavior
        self.calls = []
        self.attrs = {"State": {"ExitCode": behavior.get("exit", 0), "OOMKilled": behavior.get("oom", False)}}

    def start(self): self.calls.append("start")

    def wait(self, timeout):
        self.calls.append(("wait", timeout))
        if self.b.get("hang"):
            time.sleep(timeout + 0.1)
            raise TimeoutError("read timeout")          # stands in for requests.ReadTimeout
        if self.b.get("wait_error"):
            raise ConnectionError("daemon went away")
        return {"StatusCode": self.b.get("exit", 0)}

    def kill(self): self.calls.append("kill")
    def reload(self): self.calls.append("reload")

    def logs(self, stdout, stderr):
        return self.b.get("out", b"") if stdout else self.b.get("err", b"")

    def remove(self, force, v): self.calls.append(("remove", force, v))


class FakeClient:
    def __init__(self, behavior):
        self.created_kwargs, self.container = None, FakeContainer(behavior)
        outer = self
        self.containers = types.SimpleNamespace(create=lambda **kw: outer._create(kw))

    def _create(self, kw):
        self.created_kwargs = kw
        return self.container


def backend(behavior, **settings):
    client = FakeClient(behavior)
    s = Settings(backend="docker", max_output_bytes=settings.pop("max_output_bytes", 1024), **settings)
    return DockerBackend(s, client=client, docker_module=FAKE_DOCKER), client


class DockerBackendTests(unittest.TestCase):
    def test_hardening_flags(self):
        b, c = backend({"out": b"hi\n"})
        b.run("print('hi')", 5)
        kw = c.created_kwargs
        self.assertEqual(kw["network_mode"], "none")
        self.assertEqual(kw["mem_limit"], "128m")
        self.assertEqual(kw["memswap_limit"], "128m")           # swap disabled
        self.assertEqual(kw["nano_cpus"], 500_000_000)           # 0.5 core
        self.assertEqual(kw["pids_limit"], 64)
        self.assertTrue(kw["read_only"])
        self.assertEqual(kw["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges", kw["security_opt"])
        self.assertEqual(kw["user"], "65534:65534")
        self.assertIn("noexec", kw["tmpfs"]["/tmp"])
        self.assertEqual(kw["log_config"]["Config"]["max-size"], "1m")
        self.assertNotIn("volumes", kw)                          # no host bind mounts
        self.assertNotIn("privileged", kw)

    def test_code_is_delivered_base64_and_bootstrap_runs_it(self):
        b, c = backend({})
        b.run("print('héllo ✓')", 5)
        env = c.created_kwargs["environment"]["SANDBOX_CODE"]
        self.assertEqual(base64.b64decode(env).decode(), "print('héllo ✓')")
        self.assertEqual(c.created_kwargs["command"][-1], BOOTSTRAP)

    def test_runtime_option_passthrough(self):
        b, c = backend({}, docker_runtime="runsc")
        b.run("1", 5)
        self.assertEqual(c.created_kwargs["runtime"], "runsc")

    def test_success(self):
        b, c = backend({"out": b"42\n", "exit": 0})
        r = b.run("print(42)", 5)
        self.assertEqual((derive_status(r), r.stdout.strip()), ("success", "42"))
        self.assertIn(("remove", True, True), c.container.calls)

    def test_error_exit(self):
        b, _ = backend({"err": b"Traceback...", "exit": 1})
        r = b.run("1/0", 5)
        self.assertEqual(derive_status(r), "error")
        self.assertIn("Traceback", r.stderr)

    def test_timeout_kills_and_removes(self):
        b, c = backend({"hang": True})
        r = b.run("while True: pass", 1)
        self.assertTrue(r.timed_out)
        self.assertEqual(derive_status(r), "timeout")
        self.assertIn("kill", c.container.calls)
        self.assertIn(("remove", True, True), c.container.calls)

    def test_oom_detected(self):
        b, _ = backend({"exit": 137, "oom": True})
        self.assertEqual(derive_status(b.run("x", 5)), "oom_killed")

    def test_output_truncated(self):
        b, _ = backend({"out": b"A" * 5000, "exit": 0}, max_output_bytes=1024)
        r = b.run("x", 5)
        self.assertTrue(r.truncated)
        self.assertLess(len(r.stdout), 1200)

    def test_container_removed_even_when_wait_fails_unexpectedly(self):
        b, c = backend({"wait_error": True})
        with self.assertRaises(ConnectionError):
            b.run("x", 5)
        self.assertIn(("remove", True, True), c.container.calls)   # no leaked container

    def test_healthcheck_reports_missing_daemon(self):
        class Boom:
            def ping(self): raise OSError("no socket")
        d = DockerBackend(Settings(backend="docker"), client=Boom(), docker_module=FAKE_DOCKER)
        h = d.healthcheck()
        self.assertFalse(h["ok"]); self.assertIn("unreachable", h["detail"])


if __name__ == "__main__":
    unittest.main()
