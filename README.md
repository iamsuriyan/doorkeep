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

`site create` prints a public site key and a secret that is shown once.

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

Pre-alpha. Milestones 1 (core scoring loop) and 2 (server-side signals: IP
intelligence, velocity, JA4 and HTTP/2 fingerprints) are done.

| Setup (measured end to end in real browsers) | Risk | Outcome |
|---|---|---|
| Default headless Chromium (Playwright) | 100 | block |
| Default headless Firefox (Playwright) | 100 | block |
| playwright-extra + stealth plugin, headless | 100 | block |
| Headed Chromium over CDP, webdriver flag removed | 70 | challenged |
| Stealth plugin + synthesised human-like input | 25 | allow (known miss) |
| Script forging a perfect payload over Go TLS | 55 | challenged |
| Real Chromium, no automation | 0 | allow |

Known gaps are tracked in the open in
[testing/e2e/known_misses.yaml](testing/e2e/known_misses.yaml). Next:
server-side TLS/HTTP2 fingerprints, IP intelligence and velocity (M2), visual
and audio challenges (M3), the model layer (M4), dashboard (M5) and
integrations (M6).

The design is in [docs/design/v1.md](docs/design/v1.md). The research that
motivated the project is in [docs/research](docs/research).

## Development

```sh
make test      # Go unit and API tests, snippet unit tests
make e2e       # real-browser detection matrix (needs xvfb)
make build     # snippet + binary
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
