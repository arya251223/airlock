"""Gallery of snippets, shared by the UI and the automated tests.

Each example declares which outcomes are acceptable so the *same* list is both
the demo ("watch hostile code get contained") and the regression suite.
``needs`` names a backend capability that must be present for the expectation
to hold (e.g. a fork bomb is only contained when pids are limited).
"""
from __future__ import annotations

from typing import List, TypedDict


class Example(TypedDict, total=False):
    id: str
    group: str            # "normal" | "hostile"
    title: str
    blurb: str
    code: str
    timeout: int
    expect_status: List[str]
    expect_tripped: List[str]
    expect_stdout: str    # substring that must appear
    expect_truncated: bool
    needs: str


EXAMPLES: List[Example] = [
    dict(
        id="primes", group="normal", title="Compute primes",
        blurb="Ordinary agent-style computation: finishes well inside every limit.",
        code=(
            "def primes(n):\n"
            "    sieve = [True] * (n + 1)\n"
            "    sieve[0:2] = [False, False]\n"
            "    for i in range(2, int(n ** 0.5) + 1):\n"
            "        if sieve[i]:\n"
            "            sieve[i * i::i] = [False] * len(sieve[i * i::i])\n"
            "    return [i for i, p in enumerate(sieve) if p]\n\n"
            "p = primes(100_000)\n"
            "print(f'{len(p)} primes below 100000, largest = {p[-1]}')\n"
        ),
        timeout=5, expect_status=["success"], expect_stdout="9592 primes", expect_tripped=[],
    ),
    dict(
        id="runtime_error", group="normal", title="Crashing script",
        blurb="A normal bug: the traceback comes back to the agent so it can self-correct.",
        code="data = {'a': 1}\nprint(data['missing'])\n",
        timeout=5, expect_status=["error"], expect_tripped=[],
    ),
    dict(
        id="env_probe", group="hostile", title="Steal host secrets",
        blurb="Looks through environment variables for API keys that belong to the host.",
        code=(
            "import os\n"
            "needles = ('AIRLOCK_', 'SANDBOX_', 'API_KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'AWS_', 'GEMINI', 'OPENAI', 'ANTHROPIC')\n"
            "leaked = [k for k in os.environ if any(n in k.upper() for n in needles)]\n"
            "print('host secrets visible:', leaked)\n"
        ),
        timeout=5, expect_status=["success"], expect_stdout="host secrets visible: []", expect_tripped=[],
    ),
    dict(
        id="fs_write", group="hostile", title="Tamper with the filesystem",
        blurb="Tries to write into system directories such as /etc and /usr/bin.",
        code=(
            "for path in ('/etc/airlock_pwned', '/usr/bin/airlock_pwned', '/airlock_pwned'):\n"
            "    try:\n"
            "        open(path, 'w').write('x')\n"
            "        print('write succeeded:', path)\n"
            "    except OSError as e:\n"
            "        print('write blocked:', path, '->', type(e).__name__)\n"
        ),
        timeout=5, expect_status=["success"], expect_stdout="write blocked: /etc/airlock_pwned",
        expect_tripped=["filesystem"],
    ),
    dict(
        id="network_exfil", group="hostile", title="Phone home",
        blurb="Opens a TCP connection to an external host to exfiltrate data.",
        code=(
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1', 53), timeout=2)\n"
            "    print('connected: data could leave the box')\n"
            "except OSError as e:\n"
            "    print('network blocked:', e)\n"
        ),
        timeout=5, expect_status=["success"], expect_stdout="network blocked", expect_tripped=["network"],
    ),
    dict(
        id="infinite_loop", group="hostile", title="Infinite loop",
        blurb="Burns CPU forever. The wall-clock limit kills it and reclaims the container.",
        code="n = 0\nwhile True:\n    n += 1\n",
        timeout=2, expect_status=["timeout"], expect_tripped=["time"],
    ),
    dict(
        id="memory_bomb", group="hostile", title="Memory bomb",
        blurb="Allocates a gigabyte. The 128 MB cap stops it long before the host notices.",
        code="blob = b'x' * (1024 * 1024 * 1024)   # writes every page, so it really uses RAM\nprint('allocated 1 GB')\n",
        timeout=5, expect_status=["error", "oom_killed"], expect_tripped=["memory"],
    ),
    dict(
        id="fork_bomb", group="hostile", title="Fork bomb (bounded)",
        blurb="Spawns child processes in a loop until the process limit says no.",
        code=(
            "import os, time\n"
            "kids = 0\n"
            "try:\n"
            "    for _ in range(300):\n"
            "        pid = os.fork()\n"
            "        if pid == 0:\n"
            "            time.sleep(1)\n"
            "            os._exit(0)\n"
            "        kids += 1\n"
            "    print('forked all', kids, 'children: no process limit!')\n"
            "except OSError as e:\n"
            "    print('fork blocked after', kids, 'children:', e)\n"
        ),
        timeout=5, expect_status=["success"], expect_stdout="fork blocked", expect_tripped=["processes"],
        needs="pids_limited",
    ),
    dict(
        id="output_flood", group="hostile", title="Output flood",
        blurb="Prints megabytes of text to exhaust API memory. Output is capped and flagged.",
        code="line = 'A' * 1000\nfor _ in range(5_000):\n    print(line)\n",
        timeout=5, expect_status=["success", "output_limit"], expect_tripped=["output"],
        expect_truncated=True,
    ),
    dict(
        id="shell_escape", group="hostile", title="Spawn a shell",
        blurb="Imports subprocess to run shell commands. Flagged by the policy layer before it runs.",
        code=(
            "import subprocess\n"
            "r = subprocess.run(['id'], capture_output=True, text=True)\n"
            "print('uid inside sandbox:', r.stdout.strip())\n"
        ),
        timeout=5, expect_status=["success", "error", "blocked"], expect_tripped=[],
    ),
]


def public_examples() -> List[dict]:
    """Examples as served to the browser (the UI uses the expectations to judge containment)."""
    keys = ("id", "group", "title", "blurb", "code", "timeout", "expect_status",
            "expect_tripped", "expect_stdout", "expect_truncated", "needs")
    return [{k: e[k] for k in keys if k in e} for e in EXAMPLES]
