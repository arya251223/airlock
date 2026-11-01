"""Run every gallery payload through the configured backend and print a Markdown table.
   python -m scripts.containment_report [> docs/CONTAINMENT_RESULTS.md]
"""
import os
import platform
import sys

from app.config import Settings
from app.core.examples import EXAMPLES
from app.service import SandboxService

os.environ.setdefault("AIRLOCK_CANARY_SECRET", "host-secret-that-must-not-leak")


def main() -> int:
    svc = SandboxService(Settings(**{**Settings.from_env().__dict__, "rate_limit_per_min": 10_000}))
    h = svc.health()
    if not h["ok"]:
        print(f"Backend unavailable: {h['detail']}", file=sys.stderr)
        return 2
    caps = svc.backend.capabilities()
    print(f"# Containment results\n\n- Backend: `{svc.backend.name}` ({caps.get('isolation')})\n"
          f"- Host: {platform.platform()}, Python {platform.python_version()}\n"
          f"- Capabilities: " + ", ".join(f"{k}={v}" for k, v in caps.items()) + "\n")
    print("| Payload | Kind | Status | Limits fired | Exit | Time (ms) | Verdict |")
    print("|---|---|---|---|---|---|---|")
    ok = bad = skipped = 0
    for ex in EXAMPLES:
        if ex.get("needs") and not caps.get(ex["needs"]):
            print(f"| {ex['title']} | {ex['group']} | n/a | n/a | n/a | n/a | skipped ({ex['needs']} not enforced) |")
            skipped += 1
            continue
        r = svc.execute(ex["code"], ex["timeout"])
        good = (r["status"] in ex["expect_status"]
                and all(t in r["tripped"] for t in ex.get("expect_tripped", []))
                and (not ex.get("expect_stdout") or ex["expect_stdout"] in r["stdout"])
                and (not ex.get("expect_truncated") or r["truncated"]))
        ok += good; bad += (not good)
        print(f"| {ex['title']} | {ex['group']} | {r['status']} | {', '.join(r['tripped']) or '-'} | "
              f"{r['exit_code']} | {r['execution_time_ms']:.0f} | {'as expected' if good else 'UNEXPECTED'} |")
    print(f"\n**{ok} as expected, {bad} unexpected, {skipped} skipped.**")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
