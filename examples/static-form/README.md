# Plain HTML form

The smallest complete integration: one HTML page, one Go handler. No
framework, no build step.

```sh
doorkeep site create --name example --origin http://127.0.0.1:3000
DOORKEEP_URL=http://127.0.0.1:8080 DOORKEEP_SITE_KEY=dk_pk_... DOORKEEP_SECRET=dk_sk_... \
  go run ./examples/static-form
```

Open http://127.0.0.1:3000/.

- `index.html` loads the snippet from `/_dk/v1/dk.js` and has a
  `<div class="doorkeep" data-action="signup">` inside the form. On submit the
  snippet adds a hidden `dk-response` field.
- `main.go` proxies `/_dk/` to doorkeep (same origin) and, on `POST /signup`,
  calls `/v1/siteverify` through `pkg/verify` before doing anything. A failed
  check gets a generic message; the reasons go to your log, not the client.

The backend part is the same in any language: POST `secret`, `response` and
`expected_action` to `/v1/siteverify` and proceed only if `success` is true.
See `integrations/node`, `integrations/php` and `pkg/verify`.
