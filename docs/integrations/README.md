# Integrations

Every integration does three things: load the snippet (ideally from your own
origin under `/_dk/`), put a placeholder inside the form, and verify the
`dk-response` field on the server with your site secret.

| Stack | Package / file | Tested end to end |
|---|---|---|
| Any backend | `POST /v1/siteverify` (Turnstile-compatible) | yes |
| Go | `github.com/iamsuriyan/doorkeep/pkg/verify` | yes |
| Node.js | `@doorkeep/verify` (`integrations/node`) | unit |
| Next.js | `@doorkeep/next` (`integrations/nextjs`), example in `examples/nextjs-signup` | yes, real Next.js 16 Server Action |
| PHP | `doorkeep/verify` (`integrations/php`) | yes, PHP 8.3 against a live server |
| WordPress | plugin in `integrations/wordpress/doorkeep` | yes, real WordPress 6 (login, comments) |
| nginx | `integrations/nginx/doorkeep.conf` (auth_request) | yes, nginx 1.27 |
| Caddy | `integrations/caddy/Caddyfile` (forward_auth) | yes, Caddy 2 |
| Traefik | `integrations/traefik/dynamic.yml` (ForwardAuth) | config only |

## Forms (snippet + verify)

```html
<script src="/_dk/v1/dk.js" data-sitekey="dk_pk_..." async defer></script>
<form method="POST" action="/signup">
  ...
  <div class="doorkeep" data-action="signup"></div>
</form>
```

Server side, any language:

```
POST /v1/siteverify
secret=dk_sk_...&response=<dk-response>&expected_action=signup&remoteip=<client ip>
```

`success` is true only when the outcome is allow. `doorkeep.risk`,
`doorkeep.reasons` and `score` (reCAPTCHA v3 style, 1.0 = human) are there if
you prefer your own threshold; set the site to monitor mode in that case.

## Whole paths (edge mode)

Put expensive or abused paths (search, signup pages, `git clone` over HTTP,
APIs) behind the hosted check with your proxy's built-in auth sub-request.
See `integrations/nginx`, `integrations/caddy`, `integrations/traefik`.
Verified crawlers (Googlebot, Bingbot, GPTBot by published IP ranges) and
your allow-lists pass without a check.

## Fail mode

Every client lets you choose what happens when doorkeep is unreachable:
fail closed (refuse, the default) or fail open (let through). Use fail open
only for low-risk forms.

## Feedback

Report ground truth with `POST /v1/report` (`secret`, `event_id`, `label` =
`bot` or `human`), for example when a signup later turns out to be spam. The
WordPress plugin does this automatically when you mark a comment as spam.
