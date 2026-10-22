# WordPress with doorkeep

A complete local stack: WordPress, MariaDB, doorkeep and Caddy, with the
plugin from `integrations/wordpress` mounted read-only so edits show up
immediately.

```sh
./examples/wordpress/setup.sh
```

Then sign in at http://localhost:8000/wp-login.php. Login, registration,
lost password and comments are protected; WooCommerce checkout can be turned
on in Settings → doorkeep once WooCommerce is installed.

How it is wired:

- Caddy serves `/_dk/*` from doorkeep and everything else from WordPress, so
  the snippet loads from the site's own origin.
- The plugin verifies tokens server-to-server at `http://doorkeep:8080`.
- doorkeep and the plugin both trust the compose network (`172.28.0.0/16`)
  as proxies, so they see visitors' real addresses.
- The dashboard is published on `127.0.0.1:8081` only.

Stop with `docker compose -f examples/wordpress/docker-compose.yml down`
(add `-v` to delete the data).
