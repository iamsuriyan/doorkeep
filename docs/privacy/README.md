# Privacy

doorkeep runs on your infrastructure and talks to nobody else: no visitor
data leaves the machines you run it on. This page lists exactly what it
collects, what it keeps, for how long, and how it is pseudonymised, so you
can write your privacy notice and record of processing from it. The same
data map, with your instance's actual retention, is on the dashboard
(Instance → Privacy) and from the command line:

```sh
doorkeep export-datamap            # Markdown
doorkeep export-datamap --format json
```

## What the browser sends

The snippet sends one payload per protected action, to your doorkeep only.
High-entropy values are hashed in the browser before they are sent, and the
server reduces the rest to classes and buckets before storing anything:

| Group | Sent | Stored |
|---|---|---|
| Automation markers | webdriver flag and tamper checks, automation globals, headless markers, window geometry, plugin shape | booleans and small buckets |
| Fingerprint | user agent, screen, time zone, languages, GPU vendor/renderer, a canvas hash drawn with the session's seed, a fixed canvas hash, an audio hash, a 20-font presence mask, feature probes | browser and OS family, major version, GPU class, consistency flags (e.g. "fonts contradict the OS"); the device parts feed one keyed fingerprint hash |
| Behaviour | aggregates only: pointer path straightness and timing variation, click durations, key hold and interval variation, counts | the same aggregates, bucketed |
| Environment | permission states, storage availability, timer precision | bucketed |
| Timing | when the session started, first interaction, submit | elapsed seconds and consistency flags |

Never collected: what anyone types, form values, mouse coordinates,
individual keystrokes, the page URL beyond its origin, geolocation, media
device labels, battery, clipboard. No cookies are set except the single
functional `__dk_edge` cookie in edge mode.

## What the server keeps

| Data | Where | Kept as | Retention |
|---|---|---|---|
| Events (one per protected action) | database | risk, outcome, reason codes, bucketed features, fingerprint hash, IP hash, ASN, ASN class, country, browser/OS family | `event_retention` (default 30 days), then deleted |
| Hourly aggregates | database | counts per outcome, reason, country, browser; no per-visitor data | 13 months |
| Session nonces | database | random id, seed, day-scoped IP hash, UA hash, challenge state | about an hour after expiry |
| Canvas replay records | database | keyed hash of the seeded canvas and of the session seed | 24 hours |
| Velocity counters | memory, or Redis in cluster mode | counts keyed by keyed hashes of the address, /24 and fingerprint | at most 1 hour |
| Operator labels | with the event | bot or human | with the event |
| Allow/deny lists | database | what the operator entered (IP, CIDR, ASN, country, fingerprint prefix, UA pattern) | until removed or expired |
| Admin accounts, sessions, API tokens, audit log | database | argon2id password hashes; SHA-256 of session cookies and API tokens; who changed what | accounts until removed; sessions 12 hours; tokens until expiry or revocation |
| IP intelligence | data directory | public ASN, Tor, Spamhaus DROP, crawler range and blocklist files | refreshed weekly |
| Shared blocklist (only with `share_blocklist`) | memory | blocked-submission counts per /24 or /48 network | 24 hours; networks over the threshold are published |

Raw IP addresses, user agent strings, WebGL strings, time zone names and
language lists are never written to disk. The client IP is held in memory
for the duration of a request only.

## Pseudonymisation

All keys derive (HKDF) from the instance secret in the data directory.

- **Fingerprint:** HMAC of the stable device components, keyed per site and
  per calendar month. The same device has unrelated hashes on two sites and
  in two months, so neither doorkeep nor its operator can follow a visitor
  across sites or over time.
- **IP address:** HMAC of the /24 (IPv4) or /48 (IPv6), keyed per UTC day.
  Lookups by IP in the dashboard therefore work for today only.
- **Velocity keys:** HMAC of the address or prefix with a separate key,
  living at most an hour.
- **Rotating the instance secret** cuts all linkage with stored data.

There is deliberately no cross-site event search in the admin API, so an
operator running several sites cannot configure doorkeep into a cross-site
tracker.

## Legal basis and notices (not legal advice)

**GDPR.** Screening form submissions for automated abuse is generally
processed under legitimate interest (Art. 6(1)(f)); Recital 49 names
network and information security explicitly. doorkeep is designed for data
minimisation (Art. 5(1)(c)) and pseudonymisation (Art. 25, 32). Because the
outcome is an automated decision, every challenge has a human path: the
visual challenge has an audio alternative and no time limit, and each site
can set an `accessibility_url` shown in the challenge for anyone who cannot
complete it (Art. 22). Mention in your privacy notice that submissions are
screened for automated abuse by a system you operate.

**India's DPDP Act 2023.** Self-hosting keeps the processing in your own
infrastructure and jurisdiction. State the purpose (preventing automated
abuse of the form) in your notice; the data is limited to what that purpose
needs and is deleted on the schedule above.

**ePrivacy / cookies.** The snippet sets no cookies and keeps nothing in the
browser: to check that storage works it writes one probe key to
`localStorage` and `sessionStorage` and removes it immediately. Edge mode
sets one cookie that is strictly necessary for the protection the site owner
applies to that page.

## What you control

- `event_retention` in the configuration (the dashboard shows the value in
  force).
- Deleting single events from the dashboard or `DELETE
  /admin/v1/sites/{site}/events/{id}`.
- The instance secret: rotate it to make all stored hashes unlinkable to
  future traffic.
- IP intelligence downloads: `ipdata_auto_update: false` for air-gapped
  installs.
