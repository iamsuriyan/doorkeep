#!/usr/bin/env sh
# Starts a throwaway WordPress on http://localhost:18186 with the doorkeep
# plugin installed and configured. Host networking so WordPress and the
# browser both reach doorkeep at 127.0.0.1:18181.
#   up.sh <site_key> <secret>
set -eu
KEY="$1"; SECRET="$2"
# WordPress and WooCommerce versions under test (override to test others).
WP_IMAGE="${WP_IMAGE:-wordpress:php8.3-apache}"
WC_VERSION="${WC_VERSION:-}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/testing/wordpress"
docker rm -f dk-wp-db dk-wp >/dev/null 2>&1 || true
docker run -d --name dk-wp-db --network host -e MARIADB_ROOT_PASSWORD=root -e MARIADB_DATABASE=wp \
  -e MARIADB_USER=wp -e MARIADB_PASSWORD=wp mariadb:11 --port=13306 --bind-address=127.0.0.1 >/dev/null
docker run -d --name dk-wp --network host \
  -e WORDPRESS_DB_HOST=127.0.0.1:13306 -e WORDPRESS_DB_USER=wp -e WORDPRESS_DB_PASSWORD=wp -e WORDPRESS_DB_NAME=wp \
  -v "$HERE/ports.conf:/etc/apache2/ports.conf:ro" -v "$HERE/000-default.conf:/etc/apache2/sites-enabled/000-default.conf:ro" \
  -v "$ROOT/integrations/wordpress/doorkeep:/var/www/html/wp-content/plugins/doorkeep:ro" \
  "$WP_IMAGE" >/dev/null
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
echo "WordPress $($WP wp core version)"
# WooCommerce block checkout (opt-in: DK_WC=1; downloads WooCommerce).
rm -f "$HERE/.wc"
if [ "${DK_WC:-}" = "1" ]; then
  $WP wp plugin install woocommerce ${WC_VERSION:+--version=$WC_VERSION} --activate >/dev/null
  $WP wp option update woocommerce_cod_settings --format=json '{"enabled":"yes","title":"Cash on delivery","description":"","instructions":"","enable_for_methods":[],"enable_for_virtual":"yes"}' >/dev/null
  PRODUCT=$($WP wp wc product create --name=Door --type=simple --regular_price=10 --virtual=true --user=admin --porcelain)
  CHECKOUT=$($WP wp option get woocommerce_checkout_page_id)
  ACCOUNT=$($WP wp option get woocommerce_myaccount_page_id)
  $WP wp option update woocommerce_coming_soon no >/dev/null   # new stores start hidden
  $WP wp option patch update doorkeep_settings woocommerce 1 >/dev/null
  echo "$PRODUCT $CHECKOUT $ACCOUNT" > "$HERE/.wc"
fi
