# Forgejo / Gitea under crawler load

Open-source forges get flattened by crawlers walking every commit, blame and
archive link. Edge mode puts doorkeep in front of those pages only: a browser
passes an invisible check once an hour (one cookie), while scripted crawlers
are sent to an interstitial they cannot pass. git over HTTPS, the API,
sign-in, assets and feeds are left alone, so clones, CI and feed readers keep
working. Verified search engine crawlers (published Google and Bing ranges)
pass when IP data is loaded.

```sh
docker compose -f examples/forge-nginx/docker-compose.yml up -d --build
docker compose -f examples/forge-nginx/docker-compose.yml exec doorkeep \
  doorkeep site create --name forge --origin http://localhost:8000
# Network signals and the verified-crawler pass need IP data:
docker compose -f examples/forge-nginx/docker-compose.yml exec doorkeep doorkeep ipdata update
```

Open http://localhost:8000, create a user and a repository, then browse its
files: the first visit to a protected page shows "Checking your browser" for
a moment. `curl http://localhost:8000/<user>/<repo>/src/branch/main` gets a
redirect to the check, while `git clone http://localhost:8000/<user>/<repo>.git`
works as before.

What to tune:

- The protected `location` regex in `nginx.conf`: add paths your crawlers hit.
- For a public forge you want indexed, keep `ipdata update` running (it is
  automatic weekly) so verified crawlers pass, or add a `crawler` allow-list
  entry in the dashboard.
- Behind TLS, put the forge behind `dk-ja4` or let doorkeep terminate TLS to
  add JA4 and HTTP/2 fingerprints ([tls-termination.md](../../docs/operations/tls-termination.md)).
