# Resume bullets and interview prep

## Project line

**Airlock: Ephemeral Code-Execution Sandbox for AI Agents** | Python, FastAPI, Docker SDK, Pydantic, vanilla JS | github.com/<you>/airlock

## Bullets (pick 3 to 4)

- Built a sandboxed execution service for LLM-generated code: every request runs in a disposable Docker container with no network, 128 MB RAM (swap off), 0.5 CPU, 64-process cap, read-only filesystem, dropped capabilities and a non-root user, torn down on every code path.
- Designed layered defences: AST policy pre-check, bounded concurrency (503), per-client token-bucket rate limiting (429), API-key auth, output truncation and a wall-clock kill, behind a pluggable backend interface (Docker for production, rlimit/namespace backend for CI).
- Shipped a web UI with a one-click containment suite that fires 8 hostile payloads (fork bomb, memory bomb, network exfiltration, filesystem tampering, secret scraping, infinite loop, output flood, shell spawn) and reports which limit stopped each; the same payload list drives the automated tests.
- Wrote 57 automated tests plus 21 headless-browser checks and a CI pipeline running both backends; testing surfaced and fixed real defects (cross-run `/tmp` leakage, zombie processes exhausting per-user process limits).
- Measured on the dev backend: 68 ms p50 / 69 ms p95 per run, 27 runs/s at 4 slots, 1 s timeouts enforced within 8 ms. *(After running `make bench` with Docker, add your Docker p50/p95 here.)*

Only claim the Docker-specific numbers once you have run `make test-docker` and `make bench` yourself.

## Interview Q&A

**Why Docker and not `exec()` or RestrictedPython?** In-process sandboxes share the interpreter and are repeatedly escaped. A container puts a kernel boundary (namespaces, cgroups, seccomp, capabilities) between the code and the host.

**Is the AST filter a security control?** No, and the README and tests say so. It is a tripwire that rejects obvious abuse early and records intent. `__import__('so'+'cket')` evades it; the container's `network=none` is what actually stops the connection.

**How do you stop a fork bomb / memory bomb / infinite loop?** `pids_limit`, `mem_limit` equal to `memswap_limit` (no swap), and a wall-clock timeout that kills and force-removes the container. Each is a cgroup or daemon-enforced limit, not a promise by the code.

**Why pass code through an environment variable?** A bind mount needs the API and the daemon to share a filesystem, breaks with remote daemons and API-in-a-container, and conflicts with a read-only root. The env var is size-bounded by the 20k-char limit.

**What are the weaknesses?** Shared kernel (use gVisor/Kata/Firecracker for hostile multi-tenant use), no per-tenant quotas, in-memory rate limits (use Redis to scale out), and the Docker socket must never be exposed to the API container.

**How would you scale it?** Stateless API instances behind a load balancer, Redis for rate limits and a job queue, a warm pool of pre-created containers to cut start latency, and per-tenant quotas.

**Why did the memory-bomb payload write to every page?** `bytearray(1<<30)` uses calloc and may never touch the pages; cgroups limit resident memory, so the limit would never fire. Multiplying a bytes object forces real allocation.

**What bug did testing catch that you did not expect?** After a fork bomb, killed children stayed as zombies and still counted against the per-user process limit, so the next run failed. Cleanup now waits until the whole process group is gone, with a regression test.

**How do you know the UI cannot be attacked by program output?** Output is inserted with `textContent`; a browser test prints `<img onerror=...>` and asserts nothing executes.

**What does "contained" mean in the UI?** Each payload declares expected status, expected limit and expected output; the UI marks it contained only if the real result matches.
