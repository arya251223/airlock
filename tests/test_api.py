"""HTTP-layer tests (FastAPI TestClient). Skipped automatically if FastAPI/httpx are missing.
Run:  pip install -r requirements-dev.txt && python -m unittest tests.test_api
"""
import os
import unittest

try:
    from fastapi.testclient import TestClient
    from app.main import create_app
    HAVE_FASTAPI = True
except Exception:  # noqa: BLE001
    HAVE_FASTAPI = False

from app.config import Settings

BACKEND = os.getenv("SANDBOX_BACKEND", "process")


def client(**kw):
    s = Settings(backend=BACKEND, rate_limit_per_min=kw.pop("rate", 10_000), **kw)
    return TestClient(create_app(s))


@unittest.skipUnless(HAVE_FASTAPI, "fastapi / httpx not installed")
class ApiTests(unittest.TestCase):
    def test_index_served(self):
        r = client().get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Airlock", r.text)

    def test_static_assets(self):
        c = client()
        self.assertEqual(c.get("/static/app.js").status_code, 200)
        self.assertEqual(c.get("/static/app.css").status_code, 200)

    def test_health_config_examples(self):
        c = client()
        self.assertTrue(c.get("/api/health").json()["ok"])
        cfg = c.get("/api/config").json()
        self.assertEqual(cfg["limits"]["memory_mb"], 128)
        self.assertGreaterEqual(len(c.get("/api/examples").json()), 8)

    def test_execute_success_matches_schema(self):
        r = client().post("/api/execute", json={"code": "print(6*7)", "timeout_seconds": 5})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["status"], "success")
        self.assertEqual(body["stdout"].strip(), "42")
        for key in ("id", "exit_code", "execution_time_ms", "truncated", "backend", "tripped", "phases", "policy"):
            self.assertIn(key, body)

    def test_legacy_execute_alias(self):
        r = client().post("/execute", json={"code": "print(1)"})
        self.assertEqual(r.status_code, 200)

    def test_infinite_loop_times_out(self):
        r = client().post("/api/execute", json={"code": "while True: pass", "timeout_seconds": 1})
        self.assertEqual(r.json()["status"], "timeout")

    def test_validation_errors(self):
        c = client()
        self.assertEqual(c.post("/api/execute", json={"code": ""}).status_code, 422)
        self.assertEqual(c.post("/api/execute", json={"code": "1", "timeout_seconds": 99}).status_code, 422)
        self.assertEqual(c.post("/api/execute", json={"code": "x" * 20_001}).status_code, 422)
        self.assertEqual(c.post("/api/execute", json={}).status_code, 422)

    def test_api_key_enforced(self):
        c = client(api_key="s3cret")
        body = {"code": "print(1)"}
        self.assertEqual(c.post("/api/execute", json=body).status_code, 401)
        self.assertEqual(c.post("/api/execute", json=body, headers={"X-API-Key": "wrong"}).status_code, 401)
        self.assertEqual(c.post("/api/execute", json=body, headers={"X-API-Key": "s3cret"}).status_code, 200)
        self.assertEqual(c.get("/api/stats").status_code, 401)
        self.assertTrue(c.get("/api/config").json()["auth_required"])

    def test_rate_limit_returns_429_with_retry_after(self):
        c = client(rate=2)
        for _ in range(2):
            self.assertEqual(c.post("/api/execute", json={"code": "1"}).status_code, 200)
        r = c.post("/api/execute", json={"code": "1"})
        self.assertEqual(r.status_code, 429)
        self.assertIn("retry-after", {k.lower() for k in r.headers})

    def test_policy_block_mode_over_http(self):
        r = client(policy_mode="block").post("/api/execute", json={"code": "import subprocess"})
        self.assertEqual(r.json()["status"], "blocked")

    def test_stats_reflect_runs(self):
        c = client()
        c.post("/api/execute", json={"code": "print(1)"})
        s = c.get("/api/stats").json()
        self.assertGreaterEqual(s["total_executions"], 1)


if __name__ == "__main__":
    unittest.main()
