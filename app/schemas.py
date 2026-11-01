"""Request / response models (Pydantic v2)."""
from __future__ import annotations

from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field

Status = Literal["success", "error", "timeout", "oom_killed", "output_limit", "blocked", "internal_error"]


class ExecutionRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=20_000,
                      description="Python source to run inside the sandbox")
    timeout_seconds: int = Field(default=5, ge=1, le=15,
                                 description="Wall-clock limit for the execution")


class PolicyFinding(BaseModel):
    line: int
    category: str
    severity: str
    message: str


class PolicyInfo(BaseModel):
    verdict: str
    mode: str
    findings: List[PolicyFinding] = []


class ExecutionResponse(BaseModel):
    id: str
    status: Status
    stdout: str
    stderr: str
    exit_code: int
    execution_time_ms: float
    truncated: bool = False
    backend: str
    tripped: List[str] = Field(default_factory=list, description="Limits observed to have fired")
    phases: Dict[str, float] = Field(default_factory=dict)
    policy: PolicyInfo


class HealthResponse(BaseModel):
    ok: bool
    backend: str
    detail: str
    capabilities: dict
