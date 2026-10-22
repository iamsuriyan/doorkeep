#!/usr/bin/env sh
# Starts a throwaway WordPress on http://localhost:18186 with the doorkeep
# plugin installed and configured. Host networking so WordPress and the
# browser both reach doorkeep at 127.0.0.1:18181.
#   up.sh <site_key> <secret>
set -eu
KEY="$1"; SECRET="$2"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/testing/wordpress"
docker rm -f dk-wp-db dk-wp >/dev/null 2>&1 || true
docker run -d --name dk-wp-db --network host -e MARIADB_ROOT_PASSWORD=root -e MARIADB_DATABASE=wp \
  -e MARIADB_USER=wp -e MARIADB_PASSWORD=wp mariadb:11 --port=13306 --bind-address=127.0.0.1 >/dev/null
docker run -d --name dk-wp --network host \
  -e WORDPRESS_DB_HOST=127.0.0.1:13306 -e WORDPRESS_DB_USER=wp -e WORDPRESS_DB_PASSWORD=wp -e WORDPRESS_DB_NAME=wp \
  -v "$HERE/ports.conf:/etc/apache2/ports.conf:ro" -v "$HERE/000-default.conf:/etc/apache2/sites-enabled/000-default.conf:ro" \
  -v "$ROOT/integrations/wordpress/doorkeep:/var/www/html/wp-content/plugins/doorkeep:ro" \
  wordpress:6-php8.3-apache >/dev/null
# Wait for WordPress files and the database.
for i in $(seq 1 90); do
  if docker exec dk-wp test -f /var/www/html/wp-config.php 2>/dev/null && \
     docker exec dk-wp-db mariadb -uwp -pwp -h127.0.0.1 -P13306 -e 'select 1' wp >/dev/null 2>&1; then break; fi
  sleep 1
done
WP="docker run --rm --network host --user 33:33 --volumes-from dk-wp -e WORDPRESS_DB_HOST=127.0.0.1:13306 -e WORDPRESS_DB_USER=wp -e WORDPRESS_DB_PASSWORD=wp -e WORDPRESS_DB_NAME=wp wordpress:cli-php8.3"
$WP wp core install --url=http://localhost:18186 --title=doorkeep-wp --admin_user=admin --admin_password='correct horse battery staple' --admin_email=admin@example.com --skip-email >/dev/null
$WP wp plugin activate doorkeep >/dev/null
$WP wp option update doorkeep_settings "{\"public_url\":\"http://127.0.0.1:18181\",\"verify_url\":\"http://127.0.0.1:18181\",\"site_key\":\"$KEY\",\"secret\":\"$SECRET\",\"fail_open\":0,\"login\":1,\"register\":1,\"lostpassword\":1,\"comments\":1,\"woocommerce\":0,\"compat\":\"\"}" --format=json >/dev/null
$WP wp doorkeep test
