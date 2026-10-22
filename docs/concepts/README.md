# How doorkeep decides

This is the path one protected action takes, from the browser to your
backend. Every number below is the shipped default; most can be changed per
site.

## 1. Session

When the page loads, the snippet asks `POST /v1/session` for a one-time
**nonce** (valid 120 s) and a random **seed**. doorkeep checks the site key
and the page's origin, rate-limits by address and /24 (60 and 600 per
minute), and records a day-scoped hash of the address and a hash of the
User-Agent header. The seed is drawn into a canvas later, which binds the
payload to this session: a payload replayed under another nonce carries the
wrong canvas.

Expensive probes (audio, fonts, frame timing) start in idle time shortly
after the session arrives, so the submit itself is fast.

## 2. Signals

On submit the snippet sends its evidence to `POST /v1/submit`. The server
treats it as evidence, not truth, and adds what only it can see:

- **Automation markers:** webdriver and signs it was hidden, automation
  framework globals, headless markers, window geometry, fake `window.chrome`,
  patched native functions.
- **Consistency:** does the claimed browser match its JavaScript engine, its
  feature set, its Client Hints, its fonts, its GPU, its time zone? Does the
  User-Agent header match `navigator.userAgent`? With TLS termination (or
  `dk-ja4`), does the TLS handshake (JA4) and the HTTP/2 fingerprint match the
  claimed browser? A script can forge a payload but not a browser's handshake.
- **Behaviour (aggregates):** pointer path straightness and timing
  variation, click press durations and whether clicks land dead centre, key
  hold and interval variation, fields filled without key presses.
- **Timing truth:** elapsed time measured by the server, compared with what
  the client reports.
- **Network:** ASN class (hosting, ISP, mobile, ...), Tor exits, Spamhaus
  DROP, verified search and AI crawler ranges, time zone vs IP country.
- **Velocity:** submits per address, /24, fingerprint and site in the last
  minute, ten minutes and hour; how many networks one fingerprint appears
  from; how many devices one subnet produces; how regular the cadence is.

Everything is reduced to about 150 named, bucketed **features**
([reference](../reference/features.md)). A feature that could not be
measured is *unknown*, and unknown never adds risk: keyboard-only users,
screen readers and privacy browsers are not bots.

## 3. Rules

66 built-in rules ([reason codes](../reference/reason-codes.md)) are
expressions over the features, each with a weight. Fired weights add up to a
**risk** between 0 and 100.

- **Proof rules (floors):** webdriver, automation globals, a headless UA,
  canvas replay, a sub-40 ms submit and the DROP list prove automation. Their
  weight is a floor that nothing below can lower and no challenge can clear.
- **Human evidence** (natural pointer and typing) subtracts a little, but
  only when the device does not contradict itself, because behaviour can be
  synthesised and a contradiction cannot be explained away.
- **Privacy browsers:** with Firefox resistFingerprinting, Tor Browser or
  Brave, the fingerprint-consistency rules are switched off and a zero-weight
  profile reason is recorded. They are never a penalty.
- **Per-site overrides:** change a rule's weight, put it in **shadow** (it is
  evaluated and shown, but not enforced) or turn it off, and add custom
  rules. The rule lab replays a change over the last week of stored events
  before you save it.

## 4. Lists and the model

**Lists** run before scoring: an allow entry (IP, CIDR, ASN, country,
fingerprint, UA pattern, verified crawler, Tor) sets risk to 0, deny sets
it to 100, `always_challenge` turns an allow into a challenge. Allow wins
over deny.

The **model layer** adds at most 40 points and can never move a visitor
from allow straight to block:

- **HBOS**, an outlier score per site trained only on traffic allowed at low
  risk, scores how unusual this vector is for your site. It stays silent
  until it has seen 200 events.
- A **supervised model** (online logistic regression) learns from labels:
  `POST /v1/report`, the dashboard, and comments you mark as spam in
  WordPress. It runs in shadow until you promote it (200 labels, at least 50
  of each kind).

## 5. Outcome

| Risk | Outcome |
|---|---|
| 0 to 34 | allow |
| 35 to 74 | challenge |
| 75 to 100 | block |

Thresholds are per site and per action. **Site modes:** `enforce` (the
table above), `monitor` (always allow, record what would have happened:
start here), `challenge_only` (never block; the challenge is the only gate).

## 6. Challenges

- **Proof of work** (risk 35 to 54): many small SHA-256 puzzles bound to the
  nonce, solved invisibly in web workers, sized to take a moment on a phone.
  Harder when the site is under a surge (10 minutes running at five times
  its usual rate for that hour). Solving it subtracts 20.
- **Visual and audio challenge** (risk 55 to 74, after proof of work): five
  characters in an accessible dialog, with normal and slow audio, keyboard
  operable, no time limit, three attempts, and an optional per-site link to
  another way of getting help. Solving it subtracts 45.

A floor still applies after a challenge: proven automation stays blocked.
Like every captcha, the visual challenge can be solved by a capable model; it
is a cost and a human path, not a wall.

## 7. Token and verification

The browser always receives a token, even when blocked: the page never
learns its own score, so a bot cannot tune itself against it. The token is a
PASETO v4.local (encrypted and authenticated) bound to the site key, valid 5
minutes and **single use**.

Your backend posts it to `/v1/siteverify` (wire-compatible with Turnstile
and reCAPTCHA v3) with the site secret and gets `success` (true only for
allow), a `score` (1 = human), and doorkeep's risk, outcome and reason codes.
Use `expected_action` so a token for one form cannot be spent on another.

## Edge mode

For whole pages rather than forms (search, repository browsing), a reverse
proxy (nginx, Caddy, Traefik) asks `GET /v1/auth` before serving them.
Browsers without a valid cookie go through a hosted interstitial once an hour
and get a cookie bound to their browser family (and network, with strict IP
on). Lists are checked on every request, verified crawlers pass, API clients
get a 401 they can handle.

## What it does not do

It is not a WAF, not DDoS protection, and not account-takeover detection
beyond the bot signal. A determined attacker driving a real browser with
synthesised human input can get through per-request checks; volume and
distribution signals and your thresholds are the defence there. The
[threat model](../security/threat-model.md) and
[`known_misses.yaml`](../../testing/e2e/known_misses.yaml) record what is
measured to get through today.
