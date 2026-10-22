# NLnet Open Internet Stack: Restack application (draft)

**Status: draft for the maintainer to review and submit. Not submitted.**
Deadline: 3 November 2026, 12:00 CET, via https://nlnet.nl/propose/
(select "Restack"). Next deadline if missed: 3 January 2027.

Check before submitting: the requested amount and hourly rate, your own
experience paragraph, and that the repository is public.

---

## Proposal name

doorkeep: self-hosted, privacy-preserving bot protection for the open web

## Website / repository

https://github.com/iamsuriyan/doorkeep

## Abstract

Most websites that need protection from automated abuse (fake signups,
credential stuffing, comment spam, scraping that takes small servers down)
embed a script from Cloudflare, Google or hCaptcha. Every visitor's browser
then reports to a third party, and site owners who cannot or will not do
that (self-hosters, public institutions, small businesses under GDPR or
India's DPDP Act, open-source forges under crawler load) are left with
proof-of-work captchas, which stop simple scripts but not headless browsers.

doorkeep is an Apache-2.0, single-binary server plus a 10 KB browser snippet
that scores visitors on automation markers, browser consistency, behaviour,
TLS and HTTP/2 fingerprints and network reputation, entirely on the site
owner's infrastructure. It explains every decision with reason codes, asks
for proof of work or an accessible visual/audio check only when unsure, and
stores no raw signals: fingerprints are keyed per site and per month, IP
addresses per day. It is wire-compatible with Turnstile and reCAPTCHA
verification, ships integrations for WordPress, Next.js, nginx, Caddy,
Traefik, Go, Node.js and PHP, and has a dashboard with a rule lab that
replays a rule change over past traffic before it is enforced.

A working version exists and is measured against real browsers and
automation frameworks in CI. This grant would fund the work that turns it
into infrastructure others can depend on: an independent security review,
a public measurement corpus of automation tools, accessibility testing with
disabled users, Indic-language audio challenges, packaging, and
integrations for more stacks.

## Have you been involved with projects or organisations relevant to this project before?

[Maintainer: describe your background in web development and security,
relevant open-source work, and your work building websites for clinics and
small businesses in Tamil Nadu, which is the audience that most needs a
self-hosted option.]

## Requested amount

€40,000

## Explain what the requested budget will be used for

Milestone-based, at €[rate]/hour; the existing code (milestones 1 to 7 of the
design) was built before this proposal and is not billed.

| # | Milestone | Outcome | Budget |
|---|---|---|---|
| 1 | Security hardening for an independent review | Fuzzing of every parser (payload, ClientHello, HTTP/2, tokens) in OSS-Fuzz format; threat-model review; fixes from the NLnet-arranged security audit | €7,000 |
| 2 | Open measurement corpus | A public, versioned dataset of bucketed feature vectors from real browsers and automation tools (Playwright, Puppeteer, Selenium, stealth plugins, patchright, Camoufox, Nodriver), the harness that produces it, and published detection rates per release, so any bot-protection project can measure itself | €8,000 |
| 3 | Accessibility | Testing of the challenge flow with screen-reader, keyboard-only and switch users through a disability organisation; fixes; WCAG 2.2 AA conformance statement | €6,000 |
| 4 | Indic and multilingual challenges | Audio challenges in Tamil, Hindi and other languages, and localised challenge and interstitial text | €5,000 |
| 5 | Packaging and operations | Debian/Ubuntu packages, Helm chart, systemd hardening, backup and upgrade guides, signed releases with SBOMs | €5,000 |
| 6 | More integrations | Django, Laravel, Rails, Gitea/Forgejo edge recipes, Drupal module | €6,000 |
| 7 | Privacy documentation | DPIA template and data-processing documentation for GDPR and India's DPDP Act | €3,000 |

## Does the project have other funding sources?

No. It is a volunteer project so far.

## Compare your own project with existing or historical efforts

- **Cloudflare Turnstile, Google reCAPTCHA, hCaptcha**: effective signal
  scoring, but closed and third-party hosted; every visitor's browser
  reports to the vendor. doorkeep does the scoring on the site's own
  servers and is wire-compatible, so migration is a URL change.
- **mCaptcha, Altcha (open widget), Cap, Anubis**: open and self-hostable,
  but proof-of-work only (Anubis targets AI crawlers specifically). Proof of
  work costs a headless browser almost nothing. doorkeep uses proof of work
  only as one step after signal scoring.
- **Altcha Sentinel**: self-hosted signal scoring, but proprietary and paid
  for production use.
- **FPScanner**: an open fingerprinting library that deliberately stops at
  primitives and leaves scoring, correlation and operations to the user.
  doorkeep is that missing layer.

No OSI-licensed project combines browser-side signals, server-side TLS and
HTTP/2 fingerprints, velocity, explainable rules, accessible challenges and
a privacy-by-construction storage model.

## What are significant technical challenges you expect to solve during the project?

- Keeping false positives near zero for privacy browsers (Tor Browser,
  Firefox resistFingerprinting, Brave) and assistive technology, which
  look "unusual" by design. doorkeep already treats missing signals as
  neutral and relaxes consistency checks for privacy profiles; the
  accessibility milestone tests this with real users.
- Measuring detection honestly against fast-moving stealth tooling, and
  publishing the misses as well as the catches.
- Making the corpus useful without making it a tracking dataset: only
  bucketed, pseudonymous feature vectors, no raw fingerprints.
- Generating audio challenges in several Indic languages that are clear for
  people and costly for scripts.

## Describe the ecosystem of the project, and how you will engage with relevant actors

Users are site operators who self-host: WordPress and Next.js sites, small
businesses and clinics, public-sector sites, and open-source forges
(Gitea, Forgejo) under crawler load. The project will engage through the
WordPress plugin directory, the Anubis and forge communities (which already
asked for "proof of work but smarter"), Hacker News threads where people
asked for an open Turnstile alternative, and Indian developer communities
facing DPDP compliance. The measurement corpus is designed to be useful to
other bot-protection projects, including competitors.

## Is this project AI-related?

No. doorkeep is security infrastructure. Its optional learned layer is a
small statistical anomaly model (histogram-based outlier scoring and a
logistic regression trained on the operator's own labels) that runs inside
the binary; it is not a generative or large-model project.
