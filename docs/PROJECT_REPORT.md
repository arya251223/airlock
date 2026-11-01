# Airlock: Project Report

## 1. What was built

Project 1 from your spec (Ephemeral AI Code-Execution Sandbox), rebuilt as a complete product: a hardened execution engine, an HTTP API, a browser UI, a test suite and CI. It is deliberately more than the spec's ~60 lines, because the spec's version had security and reliability gaps (section 7).

## 2. How it works, step by step

A request to `POST /api/execute` goes through these stages:

1. **Validate (FastAPI/Pydantic).** Code must be 1 to 20,000 chars, timeout 1 to 15 s, optional `X-API-Key` checked with a constant-time comparison. Bad input returns 422/401/413.
2. **Rate limit.** A per-client token bucket (30/min default). Over the limit returns 429 with `Retry-After`.
3. **Static policy check.** The code is parsed to an AST and scanned for risky imports/calls (`socket`, `subprocess`, `os.system`, `ctypes`, `__import__`, ...). In `warn` mode findings are shown to the user; in `block` mode a HIGH finding stops the run before anything executes. This layer is advisory (see section 4).
4. **Admission control.** A bounded semaphore limits simultaneous sandboxes (4 default). If all are busy: 503 with `Retry-After`, never an unbounded queue.
5. **Create the sandbox (Docker backend).** A new container is created from the minimal `airlock-runner` image with: no network, 128 MB RAM and swap disabled, 0.5 CPU, 64 processes, read-only root, a 16 MB `noexec` tmpfs at `/tmp`, all capabilities dropped, `no-new-privileges`, user 65534, capped logs. The code is passed base64-encoded in an environment variable and executed by a tiny bootstrap.
6. **Run with a wall-clock timeout.** We wait up to the timeout. If it expires, the container is killed.
7. **Collect.** Exit code, the kernel's `OOMKilled` flag, and stdout/stderr (each truncated at 64 KB).
8. **Tear down.** The container and its volumes are force-removed in a `finally` block, on every path including failures.
9. **Classify.** Status is derived (`success`, `error`, `timeout`, `oom_killed`, `output_limit`) and a "limits that fired" list is computed (time, memory, processes, network, filesystem, output, policy).
10. **Respond and record.** The JSON response carries per-phase timings; counters and latency percentiles update `/api/stats`.

The **UI** loads `/api/config` and `/api/examples`, lets you edit code (line numbers, Tab indent, Ctrl+Enter), and renders the result as a *containment report*: verdict, exit code/time, seven "limit" tiles with fired ones highlighted, a proportional lifecycle timeline, policy findings, and stdout/stderr. **Run containment suite** executes every payload in turn and judges each against its declared expectation. All server text is inserted with `textContent`, so program output cannot inject HTML (tested).

The **process backend** (development/CI) mimics the same contract without Docker: a launcher process applies `RLIMIT_AS/CPU/FSIZE/NOFILE/NPROC`, a new network namespace, a private mount namespace with its own tmpfs `/tmp`, drops to uid 65534, then `exec`s Python; the whole process group is SIGKILLed on timeout and cleanup waits until no member (even zombies) remains.

## 3. Architecture decisions

- **Service layer independent of FastAPI.** All logic is testable without a web server; the HTTP layer is a thin adapter.
- **Two backends behind one interface**, so the full system is testable on machines without Docker, and `capabilities()` states honestly which guarantees each backend provides (the UI shows "NOT isolated" if a guarantee is missing).
- **One payload list serves as both demo and test oracle**, so the demo cannot silently drift from what is tested.
- **Code via environment variable, not bind mount**: works with remote daemons and API-in-container, compatible with a read-only rootfs.

## 4. Security model and residual risk

Layers: static policy (intent), container isolation (enforcement), service limits (abuse). Residual risks, stated plainly: shared host kernel (mitigate with gVisor/Kata/Firecracker via `SANDBOX_DOCKER_RUNTIME`); the AST check is bypassable by obfuscation (a unit test documents this); Docker socket exposure if you containerise the API carelessly; no per-tenant isolation or quota accounting (single-tenant demo).

## 5. Verification: what was actually tested

| Area | How | Result |
|---|---|---|
| Policy guard, classifier | 17 unit tests | pass |
| Service: limits, concurrency, rate limiting, error handling, stats | 10 unit tests with a fake backend | pass |
| Docker backend **logic** | 10 tests against a fake Docker client (hardening flags, base64 delivery, timeout->kill, OOM, truncation, cleanup on failure, health) | pass |
| Real execution | 9 end-to-end tests on the `process` backend: every payload in the gallery, secret isolation, no state across runs, timeout accuracy, unicode, syntax errors, block mode, concurrency | pass |
| Browser UI | 21 headless-Chromium checks (functionality, XSS inertness, shortcut, history, mobile overflow, zero external requests, no console errors) | 21/21 |
| FastAPI/Pydantic layer | wiring exercised with a throwaway shim; **11 real HTTP tests written but not executed here** | see below |
| Docker daemon | **not executed here** | see below |

Totals: **57 tests, 46 executed and passing, 11 skipped** (HTTP tests, skipped only because FastAPI could not be installed in the build environment). Raw logs: `TEST_RESULTS.txt`, `CONTAINMENT_RESULTS.md`, `UI_CHECK_RESULTS.txt`.

### What I could not verify, and how you close the gap

The build environment had no Docker daemon, no internet (so no `pip install fastapi`), and no pytest. Therefore:

1. **Docker enforcement was not observed.** Its logic is tested against a fake client, which proves we request the right flags and handle every outcome, not that Docker enforces them.
2. **The real FastAPI app was not started.**

Run these once on your machine; they are the proof for your resume:

```bash
pip install -r requirements-dev.txt
make test-docker      # full suite on real containers (includes the 11 HTTP tests)
make report           # produces the containment table for the Docker backend
make bench            # Docker latency numbers
```

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs both backends automatically on push. If something unexpected shows up on Docker (for instance a payload expectation that differs by Docker version), the failing test names it directly.

## 6. Measured output (process backend, 1 vCPU build VM)

Containment suite: **10/10 payloads behaved as expected.**

| Payload | Result | Limit that fired | Time |
|---|---|---|---|
| Compute primes | success | none | 69 ms |
| Crashing script | error (traceback returned) | none | 67 ms |
| Steal host secrets | success, `host secrets visible: []` | none | 68 ms |
| Tamper with filesystem | all writes refused | filesystem | 73 ms |
| Phone home | `Network is unreachable` | network | 72 ms |
| Infinite loop | killed | time | 2007 ms (2 s limit) |
| Memory bomb (1 GB) | MemoryError at 128 MB cap | memory | 70 ms |
| Fork bomb (bounded) | blocked after 63 children | processes | ~1.9 s |
| Output flood | truncated at 64 KB | output | 71 ms |
| Spawn a shell | flagged by policy; ran as uid 65534 | none | 67 ms |

Performance: sequential p50 **68 ms**, p95 **69 ms**; **26.9 runs/s** with 4 slots; a 1 s timeout was enforced with **5 to 8 ms overshoot**. Docker numbers will be higher (container create/start/remove adds roughly 0.3 to 1 s) and are not claimed here.

## 7. Problems in the original spec, and fixes

| Original | Problem | Fix |
|---|---|---|
| Bind-mount a host temp file | needs API and daemon to share a filesystem; unreadable (0600) by a non-root container user; conflicts with read-only rootfs | code passed as base64 env var |
| Only `network_disabled`, `mem_limit`, `cpu_quota` | swap allowed, no pid cap, root user, writable rootfs, all capabilities | `memswap_limit`, `pids_limit`, `read_only`+tmpfs, `cap_drop=ALL`, `no-new-privileges`, user 65534 |
| `except ContainerError` | unreachable with `detach=True` | outcome read from exit code/state |
| `except Exception` on timeout | any error, even a Docker failure, reported as timeout | elapsed-time check distinguishes timeout from infrastructure error |
| `container.logs()` unbounded | output flood exhausts API memory | log driver cap + truncation + `output_limit` status |
| Blocking Docker calls in `async def` | one slow run stalls the server | thread pool + bounded concurrency |
| No auth, no rate limit | trivially abusable | API key, token bucket, 429/503 |
| `python:3.11-slim` with pip | package manager and setuid binaries present | purpose-built runner image |
| Redis + BullMQ listed | BullMQ is a Node.js library; unnecessary here | removed |

## 8. Bugs found by testing during the build

1. **Shared `/tmp` leaked state between runs** (dev backend): caught by the "runs do not share state" test; fixed with a per-run private mount namespace and tmpfs.
2. **Zombie children poisoned the next run**: after a fork bomb, killed children counted against the per-UID process limit and made the next run fail; cleanup now waits until the whole process group is gone (regression test added).
3. **Network-namespace probe lied**: `/sys/class/net` does not reflect a new namespace; replaced with `/proc/self/net/dev`.
4. **UI**: `[hidden]` overridden by a display rule (API-key bar always visible); the suite hid unrelated badges; a CSS class collision pushed history badges off-screen. The last was caught from a screenshot, after which the browser check was tightened to test on-screen position.
5. **Payload validity on Docker (caught by review)**: `bytearray(1 GB)` would not consume real memory, `GPG_KEY` in the base image would be a false "secret leak", and the writable working directory contradicted a blurb; all three payloads were corrected.

## 9. Limitations and next steps

Single-tenant demo; in-memory stats and rate limits (use Redis for multi-instance); Python only; no package installation or file upload; add per-tenant quotas, audit logging, and a gVisor/Firecracker deployment profile for hostile multi-tenant use.
