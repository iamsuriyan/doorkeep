# Integrations

Every integration does three things: load the snippet (ideally from your own
origin under `/_dk/`), put a placeholder inside the form, and verify the
`dk-response` field on the server with your site secret.

| Stack | Package / file | Tested |
|---|---|---|
| Any backend | `POST /v1/siteverify` (Turnstile-compatible) | end to end |
| Plain HTML + Go | `examples/static-form` | unit, against a stand-in server |
| Go | `github.com/iamsuriyan/doorkeep/pkg/verify` | end to end |
| Node.js | `@doorkeep/verify` (`integrations/node`) | unit |
| Next.js | `@doorkeep/next` (`integrations/nextjs`), example in `examples/nextjs-signup` | end to end, real Next.js 16 Server Action; edge gate unit-tested |
| PHP | `doorkeep/verify` (`integrations/php`) | unit on PHP 8.1 and 8.4 in CI, against a live stand-in server |
| WordPress | plugin in `integrations/wordpress/doorkeep`, stack in `examples/wordpress` | end to end on real WordPress 6 (login, comments) and WooCommerce 10.2 block checkout (opt-in: `DK_WP=1 DK_WC=1 make e2e`); proxy and settings logic unit-tested in CI |
| nginx | `integrations/nginx/doorkeep.conf` (auth_request), forge example in `examples/forge-nginx` | end to end, nginx 1.27 |
| Caddy | `integrations/caddy/Caddyfile` (forward_auth) | end to end, Caddy 2 |
| Traefik | `integrations/traefik/dynamic.yml` (ForwardAuth) | end to end, Traefik 3.3 |
| Any TLS proxy | `dk-ja4` (`cmd/dk-ja4`) adds JA4 and HTTP/2 fingerprints | end to end over real TLS, HTTP/1.1 and HTTP/2 |

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

Put expensive or abused pages (search, repository browsing, archives,
signup pages) behind the hosted check with your proxy's built-in auth
sub-request. Leave paths used by non-browser clients (git over HTTPS, your
API, feeds, webhooks) unprotected or allow-listed: they cannot run the check.
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
