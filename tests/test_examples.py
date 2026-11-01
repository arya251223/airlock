"""End-to-end: run every gallery payload through the real configured backend.

Default backend is `process` (works without Docker). To exercise the production
path on a machine with Docker:   SANDBOX_BACKEND=docker python -m unittest tests.test_examples
"""
import os
import unittest

from app.config import Settings
from app.core.examples import EXAMPLES
from app.service import SandboxService

BACKEND = os.getenv("SANDBOX_BACKEND", "process")
os.environ.setdefault("AIRLOCK_CANARY_SECRET", "super-secret-host-value")   # must never be visible inside


def make_service(**kw):
    s = Settings.from_env()
    s = Settings(**{**s.__dict__, "backend": BACKEND, "rate_limit_per_min": 10_000, **kw})
    return SandboxService(s)


class GalleryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.svc = make_service()
        cls.caps = cls.svc.backend.capabilities()
        h = cls.svc.health()
        if not h["ok"]:
            raise unittest.SkipTest(f"backend '{BACKEND}' unavailable: {h['detail']}")

    def test_every_example_behaves_as_declared(self):
        for ex in EXAMPLES:
            with self.subTest(example=ex["id"]):
                if ex.get("needs") and not self.caps.get(ex["needs"]):
                    self.skipTest(f"{ex['id']}: backend lacks {ex['needs']}")
                r = self.svc.execute(ex["code"], ex["timeout"])
                self.assertIn(r["status"], ex["expect_status"], msg=r["stderr"][-300:])
                for t in ex.get("expect_tripped", []):
                    self.assertIn(t, r["tripped"], msg=f"stdout={r['stdout'][:200]!r} stderr={r['stderr'][-200:]!r}")
                if ex.get("expect_stdout"):
                    self.assertIn(ex["expect_stdout"], r["stdout"])
                if ex.get("expect_truncated"):
                    self.assertTrue(r["truncated"])

    def test_host_secret_is_not_visible_inside(self):
        r = self.svc.execute("import os\nprint(os.environ.get('AIRLOCK_CANARY_SECRET'))", 5)
        self.assertEqual(r["stdout"].strip(), "None")

    def test_runs_do_not_share_state(self):
        # Reuse of a sandbox would let run 2 see run 1's artifacts.
        if self.caps.get("fresh_tmp_per_run") is False:
            self.skipTest("backend cannot create a private /tmp here")
        self.svc.execute("import tempfile, os\nopen('/tmp/airlock_state', 'w').write('x')", 5)
        r = self.svc.execute("import os\nprint(os.path.exists('/tmp/airlock_state'))", 5)
        self.assertEqual(r["stdout"].strip(), "False")

    def test_fork_bomb_does_not_poison_the_next_run(self):
        # Regression: killed children linger as zombies and count against the per-UID
        # process limit; cleanup must wait for them so the next run still works.
        if not self.caps.get("pids_limited"):
            self.skipTest("backend has no process limit")
        fork = next(e for e in EXAMPLES if e["id"] == "fork_bomb")
        self.svc.execute(fork["code"], fork["timeout"])
        r = self.svc.execute("import subprocess\nprint(subprocess.run(['id','-u'],capture_output=True,text=True).stdout.strip())", 5)
        self.assertEqual(r["status"], "success", msg=r["stderr"][-200:])

    def test_timeout_is_honoured_within_tolerance(self):
        r = self.svc.execute("while True: pass", 2)
        self.assertEqual(r["status"], "timeout")
        self.assertLess(r["execution_time_ms"], 2000 + 1500)
        self.assertGreaterEqual(r["execution_time_ms"], 1900)

    def test_unicode_and_stderr_roundtrip(self):
        r = self.svc.execute("import sys\nprint('héllo ✓')\nprint('oops', file=sys.stderr)", 5)
        self.assertEqual(r["stdout"].strip(), "héllo ✓")
        self.assertEqual(r["stderr"].strip(), "oops")

    def test_syntax_error_is_a_normal_error(self):
        r = self.svc.execute("def broken(:\n", 5)
        self.assertEqual(r["status"], "error")
        self.assertIn("SyntaxError", r["stderr"])

    def test_block_mode_stops_shell_escape_before_execution(self):
        svc = make_service(policy_mode="block")
        r = svc.execute("import subprocess\nsubprocess.run(['id'])", 5)
        self.assertEqual(r["status"], "blocked")
        self.assertEqual(r["stdout"], "")

    def test_concurrent_executions_are_isolated(self):
        import concurrent.futures as cf
        codes = [f"print({i} * 111)" for i in range(1, 5)]
        with cf.ThreadPoolExecutor(4) as pool:
            outs = list(pool.map(lambda c: self.svc.execute(c, 5)["stdout"].strip(), codes))
        self.assertEqual(outs, [str(i * 111) for i in range(1, 5)])


if __name__ == "__main__":
    unittest.main()
