# Running several doorkeep nodes

One node with SQLite handles a lot (see the load test in `testing/load`).
Run more than one node for availability.

| Piece | Single node | Cluster |
|---|---|---|
| State (sites, nonces, events, rules, models) | SQLite in the data dir | Postgres, `database_url` |
| Velocity counters | in memory | Redis, `redis_url` |
| Secrets | generated on first run | `DOORKEEP_SECRET` and `DOORKEEP_TOKEN_KEY`, identical on every node (enforced) |

`deploy/docker-compose.cluster.yml` runs two nodes behind Caddy.

What is cluster-wide, verified by `testing/cluster` against real Postgres 17
and Redis 7:

- a session started on one node can be submitted on another;
- a nonce can be consumed once across the cluster (row locks);
- a token minted on one node verifies on any node, exactly once;
- velocity (bursts, devices across networks) counts traffic on all nodes.

Limitations in this version:

- Rule edits reach other nodes within 30 seconds (per-node cache).
- The learned models train per node and are saved to the shared database
  every five minutes; the last save wins. With a load balancer that spreads
  traffic evenly, each node learns the same population, so this is close to
  equivalent. Sticky routing is not needed.
- TLS and HTTP/2 fingerprints need each node to terminate TLS behind a TCP
  load balancer, or your proxy to forward `Doorkeep-TLS` / `Doorkeep-H2`.
- If Redis is unreachable, each node falls back to its own in-memory counts
  (session rate limits and velocity keep working, per node rather than
  cluster-wide) and logs a warning once a minute.
- Each node binds its own admin listener (`admin_listen`, default
  `127.0.0.1:8081`). Several nodes on one host need different addresses,
  e.g. `DOORKEEP_ADMIN_LISTEN=127.0.0.1:8082` for the second.
