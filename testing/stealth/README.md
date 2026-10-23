# Advanced automation tools

Drivers for the stealth tools doorkeep is measured against, used by
`testing/e2e/tests/advanced.spec.ts`:

| Tool | What it is | Driver |
|---|---|---|
| patchright | Playwright fork that removes CDP and automation leaks | in the spec (npm) |
| Camoufox | Firefox build that spoofs its fingerprint natively, humanized cursor | `camoufox_run.py` |
| Nodriver | Chromium over CDP without WebDriver or Playwright | `nodriver_run.py` |

The Python drivers declare their dependencies inline and run with `uv`
(`uv run --script ...`); nothing is installed globally. Camoufox downloads its
browser on first use (`uv run --with camoufox python -m camoufox fetch`).

What each tool is expected to do against doorkeep is recorded in
`testing/e2e/advanced.json`: `caught` (must not be allowed: a change that lets
it through fails the suite) or `miss` (gets through today, tracked in
`known_misses.yaml`; the suite only reports it).
