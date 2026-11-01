"""HTTP layer: validation, auth, error mapping, static UI. No business logic here."""
from __future__ import annotations

import hmac
import os
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import Settings
from app.core.examples import public_examples
from app.schemas import ExecutionRequest, ExecutionResponse, HealthResponse
from app.service import Busy, RateLimited, SandboxService

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


def create_app(settings: Optional[Settings] = None, service: Optional[SandboxService] = None) -> FastAPI:
    settings = settings or Settings.from_env()
    svc = service or SandboxService(settings)

    app = FastAPI(
        title="Airlock - Ephemeral AI Code-Execution Sandbox",
        version="1.0.0",
        description="Runs untrusted, AI-generated Python in a throw-away, resource-capped, "
                    "network-less container and returns structured results.",
    )
    app.state.service = svc
    app.state.settings = settings

    def require_key(x_api_key: Optional[str] = Header(default=None)) -> None:
        if settings.api_key and not (x_api_key and hmac.compare_digest(x_api_key, settings.api_key)):
            raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header")

    @app.exception_handler(RateLimited)
    async def _rate_limited(_: Request, exc: RateLimited):
        return JSONResponse(status_code=429, headers={"Retry-After": str(int(exc.retry_after) + 1)},
                            content={"detail": f"Rate limit exceeded. Retry in {exc.retry_after:.0f}s."})

    @app.exception_handler(Busy)
    async def _busy(_: Request, __: Busy):
        return JSONResponse(status_code=503, headers={"Retry-After": "1"},
                            content={"detail": "All sandbox slots are busy. Retry shortly."})

    async def _run(payload: ExecutionRequest, request: Request) -> dict:
        if len(payload.code) > settings.max_code_chars:
            raise HTTPException(status_code=413, detail=f"Code exceeds {settings.max_code_chars} characters")
        client = request.client.host if request.client else "unknown"
        # Sandbox execution blocks for up to `timeout` seconds: keep the event loop free.
        return await run_in_threadpool(svc.execute, payload.code, payload.timeout_seconds, client)

    @app.post("/api/execute", response_model=ExecutionResponse, dependencies=[Depends(require_key)])
    async def execute(payload: ExecutionRequest, request: Request):
        return await _run(payload, request)

    # Backwards-compatible alias matching the original spec.
    @app.post("/execute", response_model=ExecutionResponse, dependencies=[Depends(require_key)],
              include_in_schema=False)
    async def execute_legacy(payload: ExecutionRequest, request: Request):
        return await _run(payload, request)

    @app.get("/api/health", response_model=HealthResponse)
    async def health():
        return await run_in_threadpool(svc.health)

    @app.get("/api/config")
    async def config():
        h = await run_in_threadpool(svc.health)
        return {"limits": settings.public_limits(), "backend": svc.backend.name,
                "policy_mode": settings.policy_mode, "capabilities": h["capabilities"],
                "auth_required": bool(settings.api_key)}

    @app.get("/api/examples")
    async def examples():
        return public_examples()

    @app.get("/api/stats", dependencies=[Depends(require_key)])
    async def stats():
        return svc.stats.snapshot()

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

    return app


app = create_app()
