# Configuration

doorkeep reads an optional YAML file (`--config` or `DOORKEEP_CONFIG`) and
`DOORKEEP_*` environment variables (environment wins).

| YAML | Environment | Default | Meaning |
|---|---|---|---|
| `listen` | `DOORKEEP_LISTEN` | `:8080` | Listen address |
| `data_dir` | `DOORKEEP_DATA_DIR` | `./data` | SQLite database, generated secrets, IP data, ACME cache |
| `secret` | `DOORKEEP_SECRET` | generated | Instance secret (base64, 32+ bytes). All pseudonymisation derives from it; rotating it cuts all linkage |
| `token_keys` | `DOORKEEP_TOKEN_KEY`, `DOORKEEP_TOKEN_KEY_OLD` | generated | Token encryption keys (base64, 32 bytes). The first mints, the rest still verify (rotation) |
| `token_ttl` | | `5m` | How long a token may wait for siteverify |
| `event_retention` | | `720h` | How long events are kept (hourly aggregates are kept 13 months) |
| `trusted_proxies` | `DOORKEEP_TRUSTED_PROXIES` | none | CIDRs whose `X-Forwarded-*`, `Doorkeep-TLS` and `Doorkeep-H2` headers are honoured |
| `tls_cert`, `tls_key` | `DOORKEEP_TLS_CERT`, `DOORKEEP_TLS_KEY` | | Terminate TLS (enables JA4 and HTTP/2 fingerprints) |
| `autocert_domains`, `autocert_email` | `DOORKEEP_AUTOCERT_DOMAINS`, `DOORKEEP_AUTOCERT_EMAIL` | | Automatic certificates (TLS-ALPN-01 on the listener) |
| `ipdata_auto_update` | `DOORKEEP_IPDATA_AUTO_UPDATE` | `true` | Weekly IP intelligence download; disable for air-gapped installs |
| `database_url` | `DOORKEEP_DATABASE_URL` | | Postgres for cluster mode; requires explicit secrets |
| `redis_url` | `DOORKEEP_REDIS_URL` | | Redis for shared velocity in cluster mode |
| `log_level` | `DOORKEEP_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

Per-site settings (origins, mode, thresholds, per-action thresholds,
interactive actions, strict IP binding, accessibility link, rule overrides,
lists) live in the database and are edited in the dashboard or through
`/admin/v1`.

## Commands

```
doorkeep serve [--config path]
doorkeep site create --name NAME --origin URL [--origin URL ...] [--mode enforce|monitor|challenge_only]
doorkeep site list
doorkeep admin create --user NAME        # password on stdin
doorkeep admin token --name NAME         # bearer token for /admin/v1
doorkeep ipdata update
doorkeep migrate
doorkeep version
```
