# Load test

`go run ./testing/load` drives full session, submit and siteverify cycles
from varied client addresses (start doorkeep with
`DOORKEEP_TRUSTED_PROXIES=127.0.0.1` so `X-Forwarded-For` is honoured).

Measured 2026-10-22 on one node with SQLite, IP intelligence loaded, a
16-thread laptop, client and server on the same machine:

| Load | Endpoint | p50 | p95 | p99 | Errors |
|---|---|---|---|---|---|
| 500 cycles/s (1,496 HTTP req/s), 30 s | session | 0.32 ms | 1.05 ms | 2.51 ms | 0 |
| | submit (full scoring) | 1.08 ms | 3.6 ms | 5.0 ms | 0 |
| | siteverify | 0.42 ms | 1.05 ms | 2.73 ms | 0 |

Memory: 175 MB idle (mostly the IP intelligence tables), 227 MB after
15,000 cycles. The design target was p95 under 25 ms at 500 req/s.

The first run of this test found that the velocity tracker preallocated an
hour-long ring per key (about 7 KB each); it now stores buckets sparsely
(147 bytes per single-event key), guarded by `TestMemoryPerKey`.
