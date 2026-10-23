# doorkeep

Self-hosted bot and abuse risk scoring. The open-source equivalent of Cloudflare
Turnstile or reCAPTCHA v3: an invisible browser snippet and a single Go binary
that score a visitor on fingerprint consistency, automation markers, behaviour
and network signals, hand your backend a short-lived token to verify, and fall
back to a proof-of-work or accessible challenge only when the score is uncertain.

## Why

Every open-source captcha today (mCaptcha, Altcha, Cap, Anubis) is proof-of-work
only. It stops `curl`, not a headless browser. The tools that score real signals
are closed or paid. doorkeep is the missing scoring layer, built for people who
cannot or will not load a third-party vendor's script: self-hosters, indie SaaS
fighting signup abuse, regulated companies that must keep visitor data in-country,
and open-source forges under crawler load.

## How it works

```
page/snippet                              doorkeep server                     site backend
 POST /v1/session {site_key, action} ---> issue one-time nonce
 collect signals (invisible)
 POST /v1/submit {payload} -------------> score -> token | challenge
 [challenge] POST /v1/challenge --------> verify PoW or visual, mint token
 form POST --------------------------------------------------------------> POST /v1/siteverify
                                                                        <--- {success, score, doorkeep:{risk, reasons}}
```

The verify API is wire-compatible with Turnstile and reCAPTCHA, so migrating is a
URL change. The client never sees its own score or reasons.

## Quickstart

```sh
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml run --rm doorkeep \
  site create --name mysite --origin https://example.com
```

`site create` prints a public site key and a secret that is shown once. For
the dashboard at `http://127.0.0.1:8081/admin/` (published on localhost only),
create an admin (the password is read from stdin):

```sh
docker compose -f deploy/docker-compose.yml run --rm doorkeep admin create --user ops
```

The dashboard shows traffic by outcome, the reasons behind decisions, every
event with its signals, per-site rule overrides with a rule lab that replays
a change over the last week before you enforce it, allow and deny lists,
model status, API tokens and a privacy data map
(also `doorkeep export-datamap`).

Proxy `/_dk/` on your site to doorkeep (same origin, no CORS, not blockable as
a third-party host), then add the snippet and a placeholder inside your form:

```html
<script src="/_dk/v1/dk.js" data-sitekey="dk_pk_..." async defer></script>
<form method="POST" action="/signup">
  ...
  <div class="doorkeep" data-action="signup"></div>
  <button>Sign up</button>
</form>
```

On submit your backend receives a `dk-response` field. Verify it exactly as
you would a Turnstile token:

```sh
curl -s https://doorkeep.internal/v1/siteverify \
  -d secret=dk_sk_... -d response="$DK_RESPONSE" -d expected_action=signup
```

```json
{
  "success": true,
  "action": "signup",
  "hostname": "example.com",
  "score": 0.88,
  "error-codes": [],
  "doorkeep": { "risk": 12, "outcome": "allow", "reasons": [], "challenge": "none" }
}
```

Already using Turnstile or reCAPTCHA? Add `data-compat="turnstile"` (or
`recaptcha`) to the script tag and the snippet also fills
`cf-turnstile-response` / `g-recaptcha-response`; point your verify URL at
doorkeep.

## Status

Pre-release. All seven milestones of the [design](docs/design/v1.md) are
built: scoring loop, server-side signals (IP intelligence, velocity, JA4 and
HTTP/2 fingerprints), proof of work plus an accessible visual and audio
challenge, the learned model layer, the dashboard, integrations and edge
mode, and cluster mode on Postgres and Redis.

| Setup (measured end to end in real browsers) | Risk | Outcome |
|---|---|---|
| Default headless Chromium (Playwright) | 100 | block |
| Default headless Firefox (Playwright) | 100 | block |
| playwright-extra + stealth plugin, headless | 100 | block |
| Headed Chromium over CDP, webdriver flag removed | 70 | stopped at visual challenge |
| Stealth plugin + synthesised human-like input | 25 | allow (known miss) |
| Script forging a perfect payload over Go TLS | 55 | challenged |
| Real Chromium, no automation | 0 | allow |

Known gaps are tracked in the open in
[testing/e2e/known_misses.yaml](testing/e2e/known_misses.yaml). One node on SQLite handled 1,496 HTTP requests per second with submit p95 at
3.6 ms in the [load test](testing/load/README.md). Documentation starts at
[docs/README.md](docs/README.md).

### Integrations

Go, Node.js (with Express middleware), Next.js, Python and Django, PHP,
Laravel and WordPress clients, plus edge mode for nginx,
Caddy and Traefik (protect whole paths with the proxy's built-in auth
sub-request; no modules), and `dk-ja4`, a small TLS front that adds JA4 and
HTTP/2 fingerprints behind any proxy. Next.js, WordPress (7.1, with WooCommerce),
nginx, Caddy and Traefik are tested end to end with real browsers. See
[docs/integrations](docs/integrations) and the
[examples](examples): a plain HTML form, Next.js, a WordPress stack and
Forgejo behind nginx.

### Challenges

Risk 35 to 54 gets an invisible proof of work. Risk 55 to 74 gets proof of
work and then a five-character visual challenge with an audio alternative
(normal and slow), in an accessible dialog: labelled, keyboard-only
operable, forced-colours aware, no time pressure, and an optional
`accessibility_url` escape link per site. It passes axe-core WCAG 2.2 AA
checks in CI. Risk 75 and above is blocked. Like every captcha, the visual
challenge is solvable by a multimodal model; it is a cost and a human path,
not a security boundary.

How a decision is made is in [docs/concepts](docs/concepts/README.md), what
is collected and kept in [docs/privacy](docs/privacy/README.md). The design
is in [docs/design/v1.md](docs/design/v1.md). The research that motivated the
project is in [docs/research](docs/research).

### Operating it

Prometheus metrics and tested alert rules
([monitoring](docs/operations/monitoring.md)), `doorkeep backup` / `restore`
([backups](docs/operations/backups.md)), FireHOL and CrowdSec IP blocklists
with opt-in sharing between installs
([blocklists](docs/operations/blocklists.md)), and signed releases with SBOMs
([verifying releases](docs/operations/releases.md)).

## Development

```sh
make test      # Go unit and API tests (including the golden corpus), web unit tests
make e2e       # real-browser detection matrix and edge proxies (needs xvfb, Docker)
make fuzz      # fuzz the payload, token, TLS and HTTP/2 parsers
make build     # snippet + dashboard + binary
```

## Principles

- Neutral when absent: a missing signal never adds risk. Keyboard-only and
  screen-reader users are not bots.
- Privacy browsers get a reduced rule set, not a penalty.
- Raw signals never touch disk. Fingerprints are per-site, per-month HMACs; IPs
  are day-scoped hashes of the /24 or /48.
- The operator cannot turn doorkeep into a cross-site tracker by configuration.
- Every decision carries human-readable reason codes.

## License

Apache-2.0. See [LICENSE](LICENSE).
