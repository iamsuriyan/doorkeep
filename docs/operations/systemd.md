# Running under systemd

`deploy/systemd/doorkeep.service` runs the single binary as a hardened
service with no fixed user (`DynamicUser`), a private state directory at
`/var/lib/doorkeep`, a read-only view of the rest of the system and a
syscall filter.

```sh
install -m 0755 doorkeep /usr/local/bin/doorkeep
install -D -m 0644 deploy/systemd/doorkeep.service /etc/systemd/system/doorkeep.service
systemctl daemon-reload
systemctl enable --now doorkeep
journalctl -u doorkeep -f
```

The service listens on `:8080` for the public API and on `127.0.0.1:8081`
for the dashboard and admin API. Reach the dashboard over SSH
(`ssh -L 8081:127.0.0.1:8081 host`) or a VPN rather than publishing it.

## Creating sites and admins

CLI commands must use the same data directory and run as the service's
dynamic user (`User=doorkeep`; systemd gives units that name the same
dynamic user the same UID), so the files they create stay readable by the
service:

```sh
run() { systemd-run --pty --wait -p DynamicUser=yes -p User=doorkeep -p StateDirectory=doorkeep \
  -E DOORKEEP_DATA_DIR=/var/lib/doorkeep /usr/local/bin/doorkeep "$@"; }
run site create --name shop --origin https://shop.example.com
run admin create --user ops
```

## Binding port 443

To let doorkeep terminate TLS on `:443` (for JA4 and HTTP/2 fingerprints,
see [tls-termination.md](tls-termination.md)), set `DOORKEEP_LISTEN=:443`,
add `tls_cert`/`tls_key` or `autocert_domains` to the config, and uncomment
the two `CAP_NET_BIND_SERVICE` lines in the unit.

## Cluster mode

For several nodes, set `DOORKEEP_DATABASE_URL`, `DOORKEEP_REDIS_URL`,
`DOORKEEP_SECRET` and `DOORKEEP_TOKEN_KEY` (identical on every node) with
`Environment=` lines or an `EnvironmentFile=` readable only by root. See
[clustering.md](clustering.md).
