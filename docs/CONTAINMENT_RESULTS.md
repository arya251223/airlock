# Containment results

- Backend: `process` (process (dev only))
- Host: Linux-6.18.44-fc-v185-x86_64-with-glibc2.39, Python 3.12.3
- Capabilities: isolation=process (dev only), network_isolated=True, memory_limited=True, cpu_limited=True, pids_limited=True, readonly_rootfs=False, fresh_tmp_per_run=True, non_root=True

| Payload | Kind | Status | Limits fired | Exit | Time (ms) | Verdict |
|---|---|---|---|---|---|---|
| Compute primes | normal | success | - | 0 | 73 | as expected |
| Crashing script | normal | error | - | 1 | 39 | as expected |
| Steal host secrets | hostile | success | - | 0 | 38 | as expected |
| Tamper with the filesystem | hostile | success | filesystem | 0 | 38 | as expected |
| Phone home | hostile | success | network | 0 | 66 | as expected |
| Infinite loop | hostile | timeout | time | 124 | 2005 | as expected |
| Memory bomb | hostile | error | memory | 1 | 68 | as expected |
| Fork bomb (bounded) | hostile | success | processes | 0 | 2070 | as expected |
| Output flood | hostile | output_limit | output | 1 | 36 | as expected |
| Spawn a shell | hostile | success | - | 0 | 67 | as expected |

**10 as expected, 0 unexpected, 0 skipped.**
