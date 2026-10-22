# Threat model and known limits

doorkeep raises the cost of automated abuse; it cannot make it impossible.
This page states what it handles, what it cannot, and what has been measured.

## What a deployment gets

| Attack | Defence | Measured |
|---|---|---|
| Default headless browsers (Playwright, Puppeteer, Selenium) | automation markers, consistency, behaviour; `navigator.webdriver` is proof (floor 80) | blocked at risk 100 (Chromium, Firefox) |
| Stealth plugins, default input | fill without keys, exact-centre zero-duration clicks, font/OS contradictions, emulated network | blocked at risk 100 |
| Headed automation over CDP | behaviour; proof of work cannot clear the upper challenge band, so a visual challenge follows | stopped at the visual challenge |
| Scripts forging a perfect payload | JA4 and HTTP/2 fingerprint vs claimed browser (needs TLS at doorkeep or forwarded fingerprints) | challenged (Go client with Chrome headers) |
| Replay of a captured payload or token | one-time nonce with row-locked transitions, seed-bound canvas, single-use verify, origin/UA/subnet binding | unit and cluster tests |
| Proxy rotation, device farms, bursts | fingerprint across networks, devices per subnet, canvas across browsers, IP bursts, cadence (shared via Redis in clusters) | API and cluster tests |
| Verify oracle | the browser never sees its score; blocked tokens look the same | by design |
| Admin account attacks | argon2id, lockout, CSRF, HttpOnly SameSite=Strict sessions, audit log | API tests |

## Known misses (measured, tracked in `testing/e2e/known_misses.yaml`)

- **Stealth automation with synthesised human input** (curved mouse paths,
  jittered typing, real press durations) is allowed at risk 25. Per-request
  detection of a real browser driven carefully is not realistic. Volume and
  distribution signals are the defence.
- **The CDP console probe** no longer fires on current Chromium.
- **Visual and audio challenges are solvable by multimodal models** at low
  cost. They are a human path and a cost, not a boundary.
- **Residential proxies** cannot be identified from free data; only their
  effect on one device's fingerprint across networks is visible.
- **Corporate TLS-inspection proxies** make a genuine browser look like a
  library at the TLS layer, which is why TLS and HTTP/2 mismatches are
  evidence (challenge), not proof (block).

## Non-goals

Volumetric DDoS, WAF functions, credential-stuffing lists, client-side code
obfuscation, a shared cross-instance reputation network, native mobile SDKs,
and device attestation.

## Privacy properties

Raw signals never reach disk. Fingerprints are HMACs keyed per site and per
month, so the same device cannot be linked across sites or months. IPs are
stored as day-keyed hashes of the /24 or /48; raw IPs live in memory for at
most an hour. The admin API has no cross-site search. A malicious operator
with the source can change all of this; the design makes it visible, not
impossible.

## Reporting vulnerabilities

See [SECURITY.md](../../SECURITY.md).
