# Getting started

## 1. Run doorkeep

Docker:

```sh
docker compose -f deploy/docker-compose.yml up -d
```

Or the single binary (Linux, macOS, Windows; no dependencies):

```sh
doorkeep serve            # listens on :8080, data in ./data
```

Secrets are generated on first run in the data directory. Back that
directory up.

## 2. Load IP intelligence (optional, recommended)

```sh
doorkeep ipdata update    # also refreshed weekly while serving
```

## 3. Create a site and an admin

```sh
doorkeep site create --name shop --origin https://shop.example
doorkeep admin create --user ops      # password on stdin
```

`site create` prints a public site key and a secret that is shown once. The
dashboard is at `/admin/`.

## 4. Serve doorkeep on your origin

Proxy `/_dk/` to doorkeep from your web server (nginx, Caddy, Next.js
rewrites; see [integrations](integrations/README.md)). Same-origin delivery
means no CORS and nothing for content blockers to block as a third party.

## 5. Protect a form

```html
<script src="/_dk/v1/dk.js" data-sitekey="dk_pk_..." async defer></script>
<form method="POST" action="/signup">
  <!-- your fields -->
  <div class="doorkeep" data-action="signup"></div>
  <button>Sign up</button>
</form>
```

## 6. Verify on your server

```
POST https://<doorkeep>/v1/siteverify
secret=dk_sk_...&response=<the dk-response field>&expected_action=signup
```

Accept the request only if `success` is true. The response format is
Turnstile-compatible, with reCAPTCHA v3's `score` and doorkeep's `risk` and
`reasons` under `doorkeep`.

## 7. Start in monitor mode

In the dashboard, set the site to **Monitor**: nothing is blocked, but every
event records what would have happened. Watch the overview and events for a
few days, use the rule lab to tune, then switch to **Enforce**.
