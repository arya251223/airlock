"""Static pre-flight policy check (layer 1 of defence in depth).

IMPORTANT: this is an *advisory* tripwire, not a security boundary. Python can
obfuscate imports trivially (``__import__("so" + "cket")``). The real boundary
is the container / kernel limits applied by the backend. The value of this
layer is (a) fast rejection of obvious abuse and (b) an audit trail of
*intent* that is shown to the user next to the runtime outcome.
"""
from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from typing import List

# module -> (category, severity)
_RISKY_MODULES = {
    "socket": ("network", "high"),
    "ssl": ("network", "medium"),
    "http": ("network", "medium"),
    "urllib": ("network", "medium"),
    "requests": ("network", "medium"),
    "ftplib": ("network", "high"),
    "smtplib": ("network", "high"),
    "telnetlib": ("network", "high"),
    "subprocess": ("process", "high"),
    "multiprocessing": ("process", "medium"),
    "pty": ("process", "high"),
    "ctypes": ("native", "high"),
    "cffi": ("native", "high"),
    "resource": ("process", "medium"),
}

_RISKY_OS_CALLS = {
    "system", "popen", "fork", "forkpty", "kill", "killpg", "setuid", "setgid",
    "chroot", "execv", "execve", "execl", "execlp", "execvp", "spawnl", "spawnv",
}

_RISKY_BUILTINS = {
    "__import__": ("obfuscation", "medium"),
    "eval": ("dynamic-exec", "medium"),
    "exec": ("dynamic-exec", "medium"),
}


@dataclass
class Finding:
    line: int
    category: str
    severity: str  # "high" | "medium"
    message: str


@dataclass
class PolicyReport:
    verdict: str           # "clean" | "flagged" | "blocked" | "syntax_error"
    findings: List[Finding]
    mode: str

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "mode": self.mode,
            "findings": [asdict(f) for f in self.findings],
        }


class _Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: List[Finding] = []

    def _add(self, node: ast.AST, category: str, severity: str, msg: str) -> None:
        self.findings.append(Finding(getattr(node, "lineno", 0), category, severity, msg))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.split(".")[0]
            if root in _RISKY_MODULES:
                cat, sev = _RISKY_MODULES[root]
                self._add(node, cat, sev, f"imports '{alias.name}'")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        root = (node.module or "").split(".")[0]
        if root in _RISKY_MODULES:
            cat, sev = _RISKY_MODULES[root]
            self._add(node, cat, sev, f"imports from '{node.module}'")
        if root == "os":
            for alias in node.names:
                if alias.name in _RISKY_OS_CALLS:
                    self._add(node, "process", "high", f"imports os.{alias.name}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        f = node.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            if f.value.id == "os" and f.attr in _RISKY_OS_CALLS:
                self._add(node, "process", "high", f"calls os.{f.attr}()")
        if isinstance(f, ast.Name) and f.id in _RISKY_BUILTINS:
            cat, sev = _RISKY_BUILTINS[f.id]
            self._add(node, cat, sev, f"calls {f.id}()")
        self.generic_visit(node)


def analyze(code: str, mode: str = "warn") -> PolicyReport:
    """Parse ``code`` and report risky constructs.

    mode = "off"   -> no analysis
    mode = "warn"  -> findings are reported, execution continues
    mode = "block" -> any HIGH finding prevents execution
    """
    if mode == "off":
        return PolicyReport("clean", [], mode)
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        # Let the interpreter produce the canonical error message at runtime.
        return PolicyReport(
            "syntax_error",
            [Finding(exc.lineno or 0, "syntax", "medium", exc.msg)],
            mode,
        )
    v = _Visitor()
    v.visit(tree)
    if not v.findings:
        return PolicyReport("clean", [], mode)
    blocked = mode == "block" and any(f.severity == "high" for f in v.findings)
    return PolicyReport("blocked" if blocked else "flagged", v.findings, mode)
