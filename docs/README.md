# doorkeep documentation

- [Getting started](getting-started.md): run it, add a site, protect a form.
- [How doorkeep decides](concepts/README.md): signals, rules, model, challenges and tokens.
- [Privacy](privacy/README.md): what is collected and kept, for how long, and how it is pseudonymised.
- [Configuration](reference/configuration.md): every setting and environment variable.
- [Integrations](integrations/README.md): Go, Node.js, Next.js, PHP, WordPress, nginx, Caddy, Traefik.
- [Reason codes](reference/reason-codes.md) and [features](reference/features.md) (generated from the code).
- Operations: [TLS termination and fingerprints](operations/tls-termination.md), [clustering](operations/clustering.md), [systemd](operations/systemd.md), [monitoring](operations/monitoring.md), [backups](operations/backups.md), [blocklists and sharing](operations/blocklists.md), [verifying releases](operations/releases.md).
- Examples: [plain HTML form](../examples/static-form), [Next.js](../examples/nextjs-signup), [WordPress stack](../examples/wordpress), [Forgejo behind nginx](../examples/forge-nginx).
- Testing: [golden corpus](../testing/corpus), [fuzzing](../testing/fuzz), [known misses](../testing/e2e/known_misses.yaml).
- [Threat model and known limits](security/threat-model.md).
- [Design](design/v1.md), including where the implementation departs from it.
- [Research](research) that motivated the project.
