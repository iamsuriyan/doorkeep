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

## Status

Pre-alpha. The design is in [docs/design/v1.md](docs/design/v1.md). The research
that motivated the project is in [docs/research](docs/research).

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
