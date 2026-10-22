# Fuzzing

Go fuzz targets live next to the code they exercise, so they run as seed
tests on every `go test ./...` and can be fuzzed individually:

| Target | Package | What it checks |
|---|---|---|
| `FuzzDecode` | `internal/signals/payload` | the snippet payload decoder never panics; accepted payloads normalise cleanly |
| `FuzzOpen` | `internal/token` | malformed or mutated tokens never panic and never open |
| `FuzzParse` | `internal/signals/h2fp` | the HTTP/2 preface parser never panics |
| `FuzzParseRecords` | `internal/signals/tlsfp` | the TLS ClientHello parser never panics or over-reads |

Run all of them for a while with:

```sh
make fuzz            # 30 s per target
FUZZTIME=10m make fuzz
```

or one target:

```sh
go test -run=^$ -fuzz=FuzzDecode -fuzztime=5m ./internal/signals/payload
```

A failing input is written to the package's `testdata/fuzz/<Target>/`
directory. Commit it with the fix so it stays a regression test.
