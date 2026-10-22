# Unanswered public requests for open-source developer/security tools (state as of 2026-10-22)

Method note: HN threads were pulled through the Algolia HN API (full comment trees, not snippets) for items created 2025-01-01 onward; GitHub issue reaction counts and repo metadata (stars, last push, license, archived flag) were read live from the GitHub API on 2026-10-22. reddit/stackoverflow/x were not used. lobste.rs search returned an Anubis challenge page to both WebFetch and curl, so it could not be read (see Gaps). All star counts and "last push" dates below are as of 2026-10-22 unless labelled otherwise.

## Key Question 1: Which "Ask HN: open source alternative to X?" / "is there an open source X?" threads from 2025-2026 got no satisfactory answer?

### Takeaway
Across ~150 HN Ask/comment hits since January 2025, the requests that went unanswered or were answered only with "it's dead / it's paid / it doesn't exist" cluster around five developer-security categories: Turnstile-class bot protection that is self-hostable and open, SCIM provisioning, an OSI-licensed unified-integrations/OAuth-token layer (Merge/Nango class), an explainable WAF for compliance, and local reproduction/debugging of CI jobs. A sixth (open-source Active Directory) is repeatedly asked for but is out of solo-developer scope.

### Cited Findings

**Bot protection / Turnstile class**
- 2026-02-28, HN comment on the Turnstile redesign thread: "What are the open source options? ... I would love to know what other options are available in this space aside from Turnstile, Recaptcha and HCaptcha." The only reply offered was Anubis ("the new hotness ... billing itself as an 'AI firewall'"). — [HN 47198580](https://news.ycombinator.com/item?id=47198580)
- 2026-04-12, "Ask HN: What's your experience with PoW captchas against form spam?" (6 points, 10 comments). Commenter kay_o: "These will stop curl-based requests but will not do anything against headless browsers. mCaptcha mostly dead. It increases cost to bot only and does not stop anything unless you sign up for the monthly subscription pay per request plan from Altcha for example. Then you are in a paid Turnstile situation. And not self host." Follow-up: "'pure play' (100% local, no tracking) kind of PoW captcha doesn't do anything for if you are a target." A later commenter: "mCaptcha is mostly out of equation at this point." The OP's practical conclusion was to fall back to hCaptcha. — [HN 47739684](https://news.ycombinator.com/item?id=47739684)

**Unified API / integrations / OAuth token vault (Merge, Paragon, Nango class)**
- 2025-04-09, "Ask HN: Where Is the FOSS Alternative to Merge, Paragon, Unified, etc." — "N8n and Composio are interesting, but license restriction make it hard to use ... Feels like this is perfect for open-source. Surprised I can't find anything here." Only substantive reply: a link to ByteChef. — [HN 43636469](https://news.ycombinator.com/item?id=43636469)
- 2026-03-11, "Ask HN: Merge/Nango open source alternative?" — "Looking for a truly opensource alternative to collect oauth tokens and do integrations with in a unified api for agents ... Preferably just a single lightweight app, with some proxy api." Zero comments. — [HN 47337980](https://news.ycombinator.com/item?id=47337980)

**WAF for compliance**
- 2025-04-26, HN comment: "I'm in the position where I have to run a WAF to pass security certifications. The only open source WAFs are modsecurity and it's beta successor, coraza. These things are dumb, they just use OWASP's coreruleset which is a big pile of unreadable garbage." No replies. — [HN 43805706](https://news.ycombinator.com/item?id=43805706)
- 2025-05-30, "Self-Hosted Cloudflare Alternatives" (Ask-style post): "there isn't a good alternative to Cloudflare (Cf) in the market ... clients who wanted to self-host a platform as powerful as Cf (mainly for application security and performance)"; the OP cites "Data Privacy and Compliance" as the driver. Reply (mmarian): "you need to focus on one feature on Cloudflare to make this work ... For example, the WAF is the wide range of capabilities and sensible defaults." — [HN 44136022](https://news.ycombinator.com/item?id=44136022)

**CI local reproduction / debugging**
- 2025-12-27, in "Ask HN: What developer tool do you wish existed in 2026?" (22 points, 24 comments; OP explicitly "looking for ideas to build and open-source"): "I could use a sane CI system ... I would love to be able to have access to the same env as the CI so that I could prototype the script/job on my own machine before committing to git ... Solve this and I would pay for it." Follow-ups: "record commands as you go and allow you to rollback during testing the scripts" and "the ability to stop at a specific point in the script and ... modify any commands and execute the step and then continue ... debugging interface would be a killer feature." Nobody named an existing tool. — [HN 46345827](https://news.ycombinator.com/item?id=46345827) (comment [46400062](https://news.ycombinator.com/item?id=46400062))
- Same thread, other unanswered asks: "An LLM tool that can sit on a CI pipeline to propose what tests should be blocking" and "A runtime layer for AI agents that enforces execution boundaries: traces, replay, and a hard 'no' when something unsafe is about to run." — [HN 46345827](https://news.ycombinator.com/item?id=46345827)

**Open-source Active Directory / Entra**
- 2025-12-18, "Ask HN: Self-hosted AD/Entra ID alternative that works with Windows and Linux?" lists the state of the art: "Samba AD (works but painful, no modern protocols) - UCS/Zentyal (wrap Samba, heavyweight) - Keycloak/Authentik/etc (no Windows domain support)". Replies were sceptical of demand ("For $8 a month you can get an F3 license"). — [HN 46310562](https://news.ycombinator.com/item?id=46310562)
- 2025-06-25, HN comment: "how hard would it be to copy Active Directory in an open source project ... if orgs need this capability why is there no good open source solution?" Reply: "Massive. AD isn't just LDAP and Policies. There's somewhere around 14 services that are involved." — [HN 44382444](https://news.ycombinator.com/item?id=44382444)

**Other 2025-2026 Ask HN threads checked (answered or off-scope)**
- "Ask HN: in 2025 Which project does not have any good open-source alternatives?" (31 points, 21 comments, 2025-03-08): asks were Dropbox server ("I would contribute financially towards such a project"), Google Docs, Jira ("everything else is just so miserably bad in comparison"), Apple Preview, Paint.net, AutoCAD, Spotify. None are developer-security tools. — [HN 43304143](https://news.ycombinator.com/item?id=43304143)
- "Ask HN: Is there any good open-source alternative to MinIO?" (2026-05-01): answered with SeaweedFS, Garage, VersityGW, RustFS, hs5. Served. — [HN 47977081](https://news.ycombinator.com/item?id=47977081)
- "Ask HN: Best open source opsgenie alternatives?" (2025-10-26): only replies were a Perplexity link and "we moved to PagerDuty free"; no OSS named in-thread, although OneUptime markets itself as an incident.io alternative ([HN 43835184](https://news.ycombinator.com/item?id=43835184)). — [HN 45715452](https://news.ycombinator.com/item?id=45715452)
- "Ask HN: Software that autonomously updates your account details on every site?" (2025-08-09): "is there an open source project that could semi-autonomously update the details for all of them? Ideally it would hook into my password database..." Zero comments. — [HN 44845152](https://news.ycombinator.com/item?id=44845152)
- 2026-03-31 comment: "everyone seems to be using tailscale (and maybe cloudflare access) and that I don't see mention of open source alternatives" was answered thoroughly with Headscale, Nebula, NetBird; served. — [HN 47594108](https://news.ycombinator.com/item?id=47594108)
- "Temporary ssh containers" wish was answered with ContainerSSH. — [HN 46345827](https://news.ycombinator.com/item?id=46345827)

### Inferences
- The bot-protection ask is the strongest because two independent 2026 threads converge on the same conclusion ("PoW only raises cost; anything with real signals is paid") and the OP of one thread abandoned open source for hCaptcha.
- The Merge/Nango ask recurs a year apart with essentially no answer both times, which is unusual for HN and indicates a true gap rather than a discoverability problem.
- The WAF ask is a single comment but is driven by certification requirements ("have to run a WAF"), which tends to create paying demand.

### Gaps
- lobste.rs search is behind an Anubis challenge; could not be read. dev.to and indiehackers searches surfaced only listicles, no unanswered requests.
- HN Algolia multi-word queries are not strict phrase matches; some relevant comments may have been missed.

## Key Question 2: Which directory categories (opensourcealternative.to, alternativeto.net, awesome lists) have zero or only dead open-source entries?

### Takeaway
Directory evidence is thin: opensourcealternative.to shows Cybersecurity and Auth & SSO categories but no CI/CD or Compliance category and only exposes 20 of 500 projects per page; alternativeto lists 12 "open source" Turnstile alternatives, but every one is proof-of-work or rule-based, none offers Turnstile-class risk signals.

### Cited Findings
- opensourcealternative.to front page (500 projects total) exposes these categories: Gaming, Automation, CRM, Observability and monitoring, Communication, Social Media, Analytics, E-commerce, Database, Business intelligence, Visual Database, Developer Tools, Internal Tool, Cybersecurity, Auth & SSO. There is no CI/CD or Compliance category. Category slugs /categories/cybersecurity, /auth-sso, /ci-cd, /compliance all returned 404, so per-category counts could not be verified. — [opensourcealternative.to](https://www.opensourcealternative.to/)
- alternativeto.net lists 12 open-source alternatives to Cloudflare Turnstile: Cap Captcha (30 likes), Anubis (21), Procaptcha (15), ALTCHA (11), Friendly Captcha (11), mosparo (6), mCaptcha (4), IronWall (1), reCaptcha WordPress Plugin, Menta CAPTCHA, IconCaptcha, EU Captcha. Descriptions are all PoW ("SHA-256 proof-of-work"), rule-based ("rule-based detection") or classic image captcha. — [alternativeto.net](https://alternativeto.net/software/cloudflare-turnstile/?license=opensource)
- Friendly Captcha's open repo is only the widget ("The widget and docs for the proof of work challenge used in Friendly Captcha"), 452 stars, MIT; the scoring backend is the commercial service. — [GitHub FriendlyCaptcha/friendly-challenge](https://github.com/FriendlyCaptcha/friendly-challenge)

### Inferences
- The Turnstile category looks crowded by count but is uniform in approach; the differentiator Cloudflare sells (network-wide signals, fingerprint and behaviour scoring) has no open entry.

### Gaps
- Could not enumerate per-category project counts on opensourcealternative.to (site is client-rendered and category URLs 404). No awesome-list "no open source option" notes were found within the call budget.

## Key Question 3: Which GitHub issues/discussions ask for capabilities maintainers declined or never built, with 50+ reactions (security, dev tooling, CI, auth, compliance, observability)?

### Takeaway
The clearest long-lived, high-reaction asks are SCIM provisioning across open-source identity projects (Keycloak 312 reactions, open since 2022; experimental server only as of April 2026, client/outbound still open) and local CI parity in nektos/act; Nango's licence issues show the unified-API gap from the maintainers' side.

### Cited Findings

**SCIM**
- keycloak/keycloak #13484 "SCIM support": 312 reactions, open, created 2022-08-02, labels priority/important, 50 comments, last updated 2026-09-11. Maintainer pedroigor 2026-04-16: "we have a first release of the SCIM API and a plan to make it supported" (experimental in 26.7). Contributor woprandi 2026-07-09: "I feel the 26.7 release support is a SCIM server, not client." — [GitHub](https://github.com/keycloak/keycloak/issues/13484)
- keycloak/keycloak #43531 "Federating users from a SCIM provider": 29 reactions, open (2025-10-16); maintainer says it is "planned right after we are done with the SCIM API". — [GitHub](https://github.com/keycloak/keycloak/issues/43531)
- zitadel/zitadel #6601 "Outbound provisioning/sync user to external systems": 24 reactions, open since 2023-09-21. — [GitHub](https://github.com/zitadel/zitadel/issues/6601)
- hashicorp/boundary #2112 "User lifecycle (e.g.: OKTA SCIM)": 23 reactions, open since 2022. — [GitHub](https://github.com/hashicorp/boundary/issues/2112)
- ansible/awx #3792 "Investigate SCIM support": 43 reactions, open since 2019. — [GitHub](https://github.com/ansible/awx/issues/3792)
- Counter-evidence (demand being absorbed): better-auth #3276 "SCIM Provisioning on SSO Plugin" closed as completed 2025-11-22 (31 reactions); pocket-id #664 closed completed 2026-01-02 (30 reactions) with the maintainer noting "I'm not using any client that supports SCIM" so needed testers. — [better-auth](https://github.com/better-auth/better-auth/issues/3276), [pocket-id](https://github.com/pocket-id/pocket-id/issues/664)
- Adjacent auth ask: keycloak/keycloak #8742 "Trusted Device two factor authenticator" (remember-this-device MFA): 134 reactions, open since 2021-11-09. — [GitHub](https://github.com/keycloak/keycloak/issues/8742)

**Unified API licensing (Nango)**
- NangoHQ/nango #2802 "This isn't open source" (2024-10-02): "The homepage says this is 'The Open-source Unified API'. But it's not open source. You use a proprietary license, Elastic License 2.0 (ELv2)." Maintainer response 2025-03-14: "The tagline has been removed." — [GitHub](https://github.com/NangoHQ/nango/issues/2802)
- NangoHQ/nango #5536 "clarify self-hosted feature set" (2026-02-27), open: "Can you explain what the limited feature set is? What's limited when self-hosting the open source version?" Commenter: "the integration boundaries have never been formalised ... Its too vage and risky for us to integrate a self hosted nango." No maintainer reply; auto-marked stale 2026-04-03. — [GitHub](https://github.com/NangoHQ/nango/issues/5536)

**CI local parity**
- nektos/act top open issues: "Support for podman" 61 reactions (2020), "command not found (in image node:12.6-buster-slim, as opposed to GH Actions)" 56 reactions (2020, environment parity), "Add Ubuntu 24.04" 42, "Make GCP Workload Identity work with act" 32. act: 72,412 stars, MIT, last push 2026-08-09. — [act issues](https://github.com/nektos/act/issues?q=is%3Aissue+is%3Aopen+sort%3Areactions-%2B1-desc)
- cli/cli #9125 "Add a way to download github actions caches": 113 reactions, open since 2024-05-24. — [GitHub](https://github.com/cli/cli/issues/9125)
- github/roadmap #1191 "Parallel steps in GitHub Actions [GA]": 101 reactions, open. — [GitHub](https://github.com/github/roadmap/issues/1191)

**Captcha-project issue signals**
- mCaptcha/mCaptcha #186 "Empirical Performance Analysis and Concerns over Protection Margin for CPU-only attacks" (2025-06-09), open; repo's last push 2025-10-07. — [GitHub](https://github.com/mCaptcha/mCaptcha/issues/186)
- TecharoHQ/anubis #206 "Implement GeoIP based checks" 79 reactions (closed). — [GitHub](https://github.com/TecharoHQ/anubis/issues/206)

**Checked but not OSS-gap signals (for completeness)**
- headscale #1545 WireGuard-only peers (153), #1307 Tailnet Lock (70): feature parity asks inside an existing OSS project, not a missing category. — [headscale issues](https://github.com/juanfont/headscale/issues)
- go-gitea/gitea #3217 "Confidential (private) issues on public repo" 227 reactions, open since 2017: relates to inbound vulnerability reporting, which is excluded from this brief. — [GitHub](https://github.com/go-gitea/gitea/issues/3217)
- GitHub issue search for "open source alternative" in titles created after 2025-01-01 returned only non-security asks (Substance Painter, Outlook, Papers with Code). — [GitHub search](https://github.com/search?q=%22open+source+alternative%22+in%3Atitle+is%3Aissue+created%3A%3E2025-01-01&type=issues&s=reactions-%2B1-desc)

### Inferences
- SCIM demand is being partially absorbed by individual projects implementing their own servers (better-auth, pocket-id, Keycloak experimental), but the outbound/client side and a reusable, conformance-tested SCIM layer remain unbuilt.
- Nango's unanswered licence-boundary question suggests teams actively want to embed a self-hosted integrations layer and are blocked by licence ambiguity, not by features.

### Gaps
- GitHub Discussions (as opposed to Issues) are not covered by the issues search API; high-reaction discussions in orgs/community were not checked.
- No 50+ reaction issue was found that was explicitly "declined/wontfix" by maintainers in these categories; the signal is "open for years" rather than "declined".

## Key Question 4: For each candidate, what exists today and why do people still ask? (ranked list)

### Takeaway
Eight candidates are backed by a public request; the top three (self-hosted bot-risk scoring, SCIM sidecar, OSI-licensed OAuth connection vault) each have 2+ independent 2025-2026 asks and only paid, dead, or primitives-only open options. Two further asks (compliance automation, dependency firewall) were filled during 2025-2026 and are listed so the reader does not rebuild them.

### Cited Findings

#### 1. Self-hosted, open bot/abuse risk scoring (Turnstile class, not just PoW) — demand: strong
- Requests: [HN 47198580](https://news.ycombinator.com/item?id=47198580) (2026-02-28), [HN 47739684](https://news.ycombinator.com/item?id=47739684) (2026-04-12), quoted in KQ1.
- What exists: mCaptcha 2,495 stars, AGPL-3.0, last push 2025-10-07 (12 months stale; HN users call it "mostly dead") — [GitHub](https://github.com/mCaptcha/mCaptcha). Altcha widget 2,842 stars, MIT, active, PoW only — [GitHub](https://github.com/altcha-org/altcha); Altcha Sentinel (the version with "interaction-based, contextual, and machine-learning-based" signals) is self-hosted but proprietary: "A paid Professional or Enterprise license is required before using it in production" and no Sentinel repo exists among altcha-org's public repos — [altcha.org pricing](https://altcha.org/pricing/), [altcha-org GitHub](https://github.com/altcha-org). Pricing sources conflict: the pricing page fetched showed Professional €99/month and Enterprise €799/month, while the docs plans page indexed by search shows Starter €24, Professional €74, Enterprise €600 per instance — [altcha docs plans](https://altcha.org/docs/sentinel/plans/). Cap 8,127 stars, Apache-2.0, active; PoW plus "instrumentation, which can also be configured to stop autonomous AI agents" — [GitHub](https://github.com/tiagozip/cap). Anubis 23,615 stars, MIT, active, scoped to AI-crawler gating — [GitHub](https://github.com/TecharoHQ/anubis). FPScanner 791 stars, MIT, revived in 2026 "after more than 7 years without any updates", sponsored by Castle; README: "This library focuses on self-hosted fingerprinting and bot detection primitives ... teams often need additional capabilities such as traffic observability, historical analysis, rule iteration, and correlation across device, network, and behavioral signals" which it "intentionally does not cover" — [GitHub](https://github.com/antoinevastel/fpscanner). PrivateCaptcha 198 stars, PolyForm Noncommercial (not OSI) — [GitHub](https://github.com/PrivateCaptcha/PrivateCaptcha). mosparo 311 stars, MIT, rule-based form spam — [GitHub](https://github.com/mosparo/mosparo). Procaptcha 304 stars, Apache-2.0 — [GitHub](https://github.com/prosopo/captcha).
- Why people still ask: every OSI-licensed option is PoW/rule-based; the one that adds signals (Sentinel) is paid, and the one open signal library (FPScanner) explicitly stops at primitives.

#### 2. SCIM 2.0 sidecar/gateway: drop-in SCIM server for any app + outbound provisioning for OSS IdPs — demand: strong
- Requests: Keycloak #13484 (312 reactions), #43531, Zitadel #6601, Boundary #2112, AWX #3792 (KQ3). Context: HN "Vendors that treat single sign-on as a luxury feature" (2025-08-19) debate on the SSO tax ("SSO is a clunky and complex feature to manage in a secure way") — [HN 44956908](https://news.ycombinator.com/item?id=44956908).
- What exists: jelhub/scimgateway 231 stars, MIT, active (Node, plugin-based) — [GitHub](https://github.com/jelhub/scimgateway); elimity-com/scim 252 stars, MIT, Go library, last push 2026-07-28 — [GitHub](https://github.com/elimity-com/scim); apache/directory-scimple 104 stars, Apache-2.0 — [GitHub](https://github.com/apache/directory-scimple); imulab/go-scim 170 stars, last push 2026-05-08 — [GitHub](https://github.com/imulab/go-scim); Metatavu/keycloak-scim-server 95 stars, Apache-2.0 — [GitHub](https://github.com/Metatavu/keycloak-scim-server); Captain-P-Goldfish/scim-for-keycloak 209 stars, last push 2024-03-10 (stale) — [GitHub](https://github.com/Captain-P-Goldfish/scim-for-keycloak).
- Why people still ask: existing pieces are libraries or IdP-specific plugins; there is no packaged, conformance-tested server a SaaS can deploy next to its app, and OSS IdPs still lack the client/outbound side.

#### 3. OSI-licensed OAuth connection vault + proxy ("lightweight Nango") — demand: strong
- Requests: [HN 43636469](https://news.ycombinator.com/item?id=43636469) (2025-04), [HN 47337980](https://news.ycombinator.com/item?id=47337980) (2026-03, zero replies), Nango #2802 and #5536 (KQ3).
- What exists: Nango 12,931 stars, Elastic License 2.0, free self-host "with a limited feature set" that maintainers have not defined — [GitHub](https://github.com/NangoHQ/nango); Panora 1,034 stars, AGPL-3.0, archived, last push 2025-10-26 — [GitHub](https://github.com/panoratech/Panora); Revert 1,013 stars, AGPL-3.0, last push 2025-04-07 (dormant) — [GitHub](https://github.com/revertinc/revert); Supaglue 427 stars, MIT, archived 2024 — [GitHub](https://github.com/supaglue-labs/supaglue); ByteChef 1,043 stars, Apache-2.0 core with an EE directory, positioned as workflow automation rather than a unified API — [GitHub](https://github.com/bytechefhq/bytechef).
- Why people still ask: the three OSI-licensed attempts are dead/archived and the live one is source-available with unclear self-host limits.

#### 4. Explainable, compliance-oriented WAF (not CRS regex) — demand: medium (single strong comment plus Cloudflare thread)
- Requests: [HN 43805706](https://news.ycombinator.com/item?id=43805706) (2025-04-26), [HN 44136022](https://news.ycombinator.com/item?id=44136022) (2025-05-30).
- What exists: ModSecurity 9,823 stars, Apache-2.0, still pushed 2026-10-15 (the "dead" reputation is outdated) — [GitHub](https://github.com/owasp-modsecurity/ModSecurity); Coraza 3,926 stars, Apache-2.0 — [GitHub](https://github.com/corazawaf/coraza); OWASP CRS 3,308 stars — [GitHub](https://github.com/coreruleset/coreruleset); BunkerWeb 11,094 stars, AGPL-3.0 (bundles ModSecurity + CRS behind NGINX) — [GitHub](https://github.com/bunkerity/bunkerweb), Show HN 106 points — [HN 44463747](https://news.ycombinator.com/item?id=44463747).
- Why people still ask: all open options share one rule corpus (CRS) whose findings are hard to read and tune; the compliance buyer wants auditor-friendly rules and reports, not a regex engine.

#### 5. CI job debugger / local parity (breakpoints, step replay, same env) — demand: medium
- Requests: [HN 46400062](https://news.ycombinator.com/item?id=46400062) and replies (2025-12-27) in [HN 46345827](https://news.ycombinator.com/item?id=46345827); act parity issues (KQ3).
- What exists: nektos/act 72,412 stars, MIT, last push 2026-08-09 — [GitHub](https://github.com/nektos/act); gitlab-ci-local 4,128 stars, MIT, active — [GitHub](https://github.com/firecow/gitlab-ci-local).
- Why people still ask: act reproduces the workflow file, not the runner image ("command not found ... as opposed to GH Actions"), and neither tool offers stop/modify/continue debugging.

#### 6. Tamper-evident audit log service that auditors accept — demand: weak-to-medium (builder-side evidence only)
- Requests/claims: Show HN Spine (2026-01-22): "How do you actually prove that logs haven't been modified after the fact? Most logging stacks (Splunk, Datadog, ELK) are great for analytics, but when auditors ask 'how do you prove integrity'..." (2 points) — [HN 46716265](https://news.ycombinator.com/item?id=46716265); Traceprompt "tamper-proof logs for every LLM call ... WORM logs auditors trust" (2025-07-23) — [HN 44657913](https://news.ycombinator.com/item?id=44657913); Halo "tamper-evident runtime evidence for AI agents" by an ex-Vanta engineer, 37 points, 23 comments (2026-07-07) — [HN 48818098](https://news.ycombinator.com/item?id=48818098).
- Why it is listed: at least three independent builders converged on the same problem in 12 months, but no user-side "is there an open source X" request was found; treat as a hypothesis.

#### 7. Open-source Active Directory / Entra replacement — demand: medium, scope: not solo-buildable
- Requests: [HN 46310562](https://news.ycombinator.com/item?id=46310562), [HN 44382444](https://news.ycombinator.com/item?id=44382444) (KQ1).
- What exists: Kanidm 5,490 stars, MPL-2.0, active (no Windows domain join) — [GitHub](https://github.com/kanidm/kanidm); Samba AD, FreeIPA, UCS (per the Ask HN). HN replies: AD is "around 14 services" and buyers accept "$8 a month ... F3 license".
- Listed so the reader can rule it out: multi-year, multi-protocol effort.

#### 8. Bulk account-detail/email migration agent across hundreds of SaaS accounts — demand: weak (1 point, 0 comments)
- Request: [HN 44845152](https://news.ycombinator.com/item?id=44845152) (2025-08-09).
- What exists: nothing named in-thread; no open-source project was found in this research.

#### Filled during 2025-2026 (do not rebuild)
- Compliance automation (Vanta/Drata): Comp AI 2,050 stars, AGPL-3.0, active — [GitHub](https://github.com/trycompai/comp) (Show HN [43879895](https://news.ycombinator.com/item?id=43879895)); Probo 1,475 stars, MIT, active — [GitHub](https://github.com/getprobo/probo) (Show HN [42711545](https://news.ycombinator.com/item?id=42711545), 30 points). Residual friction: Comp issue #1705 "Self-hosting is difficult due to missing documentation and Docker configuration" (closed) — [GitHub](https://github.com/trycompai/comp/issues/1705).
- Dependency/package firewall: SafeDep PMG 553 stars, Apache-2.0, active — [GitHub](https://github.com/safedep/pmg) (Show HN [48994997](https://news.ycombinator.com/item?id=48994997), 2026-07-21); DepGate announced 2026-10-21 — [HN 50179727](https://news.ycombinator.com/item?id=50179727).
- Zero-trust access / Tailscale control plane: Headscale 44,871 stars BSD-3 — [GitHub](https://github.com/juanfont/headscale); NetBird 30,130 stars (BSD-3 plus AGPL for management/signal/relay; an HN user cites an "SSO tax" in its OSS version — [HN 44529821](https://news.ycombinator.com/item?id=44529821)); Octelium 4,110 stars AGPL — [GitHub](https://github.com/octelium/octelium); Nebula 18,459 stars MIT.
- Session replay: OpenReplay 13,027 stars (multi-licence with ee/) — [GitHub](https://github.com/openreplay/openreplay); RePlaya archived 2026-06 — [GitHub](https://github.com/s2-streamstore/replaya).
- Device management (Jamf/Kandji class): Fleet 7,019 stars, MIT core plus EE directory — [GitHub](https://github.com/fleetdm/fleet). No 2025-2026 HN request for an open-source MDM was found.
- Disposable-email detection: three Show HNs in 2025-2026 ([HN 47960525](https://news.ycombinator.com/item?id=47960525), [HN 47571804](https://news.ycombinator.com/item?id=47571804)).

### Inferences
- Ranking by demand evidence: (1) bot-risk scoring, (2) SCIM sidecar, (3) OAuth connection vault, (4) compliance WAF, (5) CI debugger, (6) tamper-evident audit log, (7) open AD (excluded on scope), (8) account-migration agent.
- For a solo security/web developer, candidates 1, 2 and 3 are each buildable as a single service plus a client widget/SDK within months: 1 can reuse FPScanner primitives and Cap's widget model; 2 can reuse elimity-com/scim or go-scim; 3 is an OAuth broker with a token store and reverse proxy, deliberately not a 1,000-connector catalogue.
- Licence choice matters in these categories: the complaints about Nango (ELv2), PrivateCaptcha (PolyForm NC) and NetBird (AGPL control plane, "SSO tax") show the audience distinguishes OSI from source-available.

### Gaps
- No user-side request was found for the audit-log candidate; the evidence is three builders, not buyers.
- Could not confirm current Altcha Sentinel prices (two fetched sources disagree; both agree it is paid for production and not open source).
- lobste.rs, Reddit and X were not read, so demand signals from those communities are absent.
- Did not quantify "thumbs up 50+ and declined" issues in GitHub Discussions, only Issues.
