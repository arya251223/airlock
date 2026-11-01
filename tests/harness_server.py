"""Zero-dependency stand-in for app/main.py, used ONLY to test the browser UI where
FastAPI cannot be installed. It serves the same static files and implements the same
JSON contract on top of the real SandboxService (so the executor behind it is real).
Run:  python -m tests.harness_server 8765
"""
import json
import mimetypes
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.config import Settings
from app.core.examples import public_examples
from app.service import Busy, RateLimited, SandboxService

STATIC = os.path.join(os.path.dirname(__file__), "..", "app", "static")
SETTINGS = Settings.from_env()
SVC = SandboxService(SETTINGS)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, code, obj, headers=None):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)

    def _file(self, path):
        full = os.path.normpath(os.path.join(STATIC, path))
        if not full.startswith(os.path.normpath(STATIC)) or not os.path.isfile(full):
            return self._json(404, {"detail": "not found"})
        b = open(full, "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(full)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/": return self._file("index.html")
        if p.startswith("/static/"): return self._file(p[len("/static/"):])
        if p == "/api/health": return self._json(200, SVC.health())
        if p == "/api/config":
            return self._json(200, {"limits": SETTINGS.public_limits(), "backend": SVC.backend.name,
                                    "policy_mode": SETTINGS.policy_mode,
                                    "capabilities": SVC.health()["capabilities"], "auth_required": False})
        if p == "/api/examples": return self._json(200, public_examples())
        if p == "/api/stats": return self._json(200, SVC.stats.snapshot())
        self._json(404, {"detail": "not found"})

    def do_POST(self):
        if self.path not in ("/api/execute", "/execute"):
            return self._json(404, {"detail": "not found"})
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        code, t = body.get("code", ""), int(body.get("timeout_seconds", 5))
        if not code or len(code) > SETTINGS.max_code_chars or not 1 <= t <= 15:
            return self._json(422, {"detail": [{"msg": "invalid request"}]})
        try:
            self._json(200, SVC.execute(code, t, self.client_address[0]))
        except RateLimited as e:
            self._json(429, {"detail": f"Rate limit exceeded. Retry in {e.retry_after:.0f}s."}, {"Retry-After": "5"})
        except Busy:
            self._json(503, {"detail": "All sandbox slots are busy. Retry shortly."})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
