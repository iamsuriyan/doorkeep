# TLS termination and connection fingerprints

doorkeep can only see a client's TLS ClientHello (JA4) and HTTP/2 settings
(Akamai-style fingerprint) on connections it terminates itself. These two
signals are what catch scripts that forge a perfect browser payload: a Python,
Go or Node client cannot produce a browser's handshake.

## Option 1: doorkeep terminates TLS (recommended)

```yaml
listen: ":443"
tls_cert: /etc/doorkeep/cert.pem
tls_key: /etc/doorkeep/key.pem
# or, for automatic certificates (TLS-ALPN-01 on this listener):
# autocert_domains: ["dk.example.com"]
# autocert_email: ops@example.com
```

Point the snippet at `https://dk.example.com/v1/dk.js` (cross-origin mode). If
you prefer same-origin delivery, have your reverse proxy pass `/_dk/` through
at layer 4 (TCP/SNI routing, e.g. HAProxy `mode tcp` or Nginx `stream`) so the
TLS session still ends at doorkeep.

## Option 2: your proxy terminates TLS and forwards fingerprints

Add the proxy to `trusted_proxies` and forward:

| Header | Value |
|---|---|
| `Doorkeep-TLS` | `ja4=<JA4 string>` |
| `Doorkeep-H2` | Akamai text form `settings\|window\|priority\|pseudo` |

Headers from untrusted peers are ignored. Without either option, TLS and
HTTP/2 rules simply do not fire; nothing is treated as suspicious.

## What the fingerprints mean (measured 2026-10-22)

| Client | JA4 cipher hash | HTTP/2 class |
|---|---|---|
| Chromium 156 (headless and headed) | 8daaf6152771 | chrome |
| Firefox 157 | 8daaf6152771 | firefox |
| curl 8.18, Python urllib / requests | 1d37bd780c83 | curl (curl only) |
| Go net/http | f57a46bbacb6 | go |
| Node fetch | b262b3658495 | HTTP/1.1 only |

TLS separates browsers from HTTP libraries but not browsers from each other:
Firefox 157 and Chromium share a cipher list. HTTP/2 separates the browsers.
Re-measure with `go run ./testing/tlsclients/measure` after major browser
releases.

## Known false-positive source: TLS-inspecting proxies

Corporate TLS inspection (Zscaler, Netskope, Palo Alto decryption and similar)
re-originates the connection, so a genuine Chrome user arrives with the
proxy's handshake. For that reason `UA_TLS_MISMATCH` (45) and
`UA_H2_MISMATCH` (35) are evidence, not proof: on their own they lead to a
challenge, never a block. If your audience is mostly enterprise users behind
such proxies, consider an allow-list entry for the proxy's ASN or lowering the
weights in a site rule override.
