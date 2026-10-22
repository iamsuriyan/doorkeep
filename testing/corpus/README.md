# Golden corpus

Labelled feature vectors with the outcome doorkeep must reach for them.
`internal/scoring/rules/corpus_test.go` runs every file here through the
built-in rules and the decision engine (default thresholds, enforce mode)
on every `go test ./...`, so a rule change that lets a known bot through, or
starts penalising a known human, fails CI.

Each file is one case:

```json
{
  "name": "what this is",
  "source": "where the vector comes from",
  "action": "signup",
  "features": { "num": { "auto.wd": 1 }, "cat": { "fp.ua_family": "chrome" } },
  "expect": {
    "outcome": "allow | challenge | block",
    "min_risk": 0, "max_risk": 100,
    "fires": ["RULE_ID"], "not_fires": ["RULE_ID"],
    "note": "why this case matters"
  }
}
```

Keys are the stored feature names (`docs/reference/features.md`); an unknown
key or categorical value fails the test. Features you leave out are unknown,
which is neutral, so a vector only needs the signals that matter.

## Where the vectors come from

The current cases are built from the measurements recorded in
`testing/e2e` (detection matrix, stealth runs, `known_misses.yaml`) and from
the design's fairness cases (keyboard-only, Tor Browser, Brave, mobile).
They are not captures of production traffic. To add a real case, open the
event in the dashboard (or `GET /admin/v1/sites/{site}/events/{id}`), copy
the grouped features into a new file, label it, and state the source.
Never add anything that is not already bucketed: the corpus holds the same
pseudonymous features doorkeep stores, nothing raw.

## Known misses

`stealth-synthesised-human-input.json` records a setup doorkeep allows
(risk 25). The case pins that risk so the guard that stops synthesised
behaviour from cancelling a device contradiction cannot regress. Move such a
case to `block` or `challenge` when detection improves.
