# Monitoring

doorkeep serves Prometheus metrics at `/metrics` on the admin listener
(default `127.0.0.1:8081`, no credentials needed there). If you run the admin
routes on the public listener (`admin_listen: public`), `/metrics` requires an
admin bearer token (`doorkeep admin token --name prometheus`).

```yaml
# prometheus.yml
scrape_configs:
  - job_name: doorkeep
    static_configs: [{ targets: ["127.0.0.1:8081"] }]
rule_files: [doorkeep-alerts.yml]   # deploy/prometheus/alerts.yml
```

| Metric | Type | Meaning |
|---|---|---|
| `doorkeep_http_requests_total{route,code}` | counter | Requests by route pattern and status |
| `doorkeep_http_request_duration_seconds{route}` | histogram | Latency by route |
| `doorkeep_submits_total{site,outcome}` | counter | Scored submissions, outcome before any challenge |
| `doorkeep_tokens_total{site,outcome,challenge}` | counter | Tokens issued, final outcome and challenge passed |
| `doorkeep_challenges_total{kind,result}` | counter | Proof of work / visual answers: ok, fail, exhausted |
| `doorkeep_verifications_total{result}` | counter | siteverify: success, failure, invalid |
| `doorkeep_edge_decisions_total{result}` | counter | Edge mode: pass, check, deny |
| `doorkeep_rate_limited_total` | counter | Sessions refused by the per-address limit |
| `doorkeep_internal_errors_total{op}` | counter | Store or minting failures |
| `doorkeep_ipdata_entries{kind}` | gauge | Loaded IP intelligence (ASN ranges, Tor, DROP, blocklists) |
| `doorkeep_ipdata_updated_time_seconds` | gauge | Last IP data download |
| `doorkeep_velocity_keys` | gauge | In-memory velocity keys |
| `doorkeep_redis_errors_total` | counter | Redis failures (cluster mode falls back to per-node counts) |
| `doorkeep_build_info{version}`, `go_*` | gauge | Version, goroutines, memory |

`deploy/prometheus/alerts.yml` alerts on: an instance down, more than 2% of
requests failing, submit p95 above 250 ms, IP data older than 14 days, Redis
errors, and more than half of a site's submissions blocked (an attack, or a
rule change blocking real people). The rules are unit-tested with
`promtool test rules deploy/prometheus/alerts_test.yml`.
