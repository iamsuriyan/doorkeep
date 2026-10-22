#!/usr/bin/env sh
# Starts WordPress + doorkeep and configures the plugin. Idempotent enough to
# re-run; it creates a new doorkeep site each time.
set -eu
cd "$(dirname "$0")"
URL=http://localhost:8000
docker compose up -d --build
echo "waiting for the database and WordPress files..."
for i in $(seq 1 120); do
  if docker compose exec -T wordpress test -f /var/www/html/wp-config.php 2>/dev/null && \
     docker compose exec -T db mariadb -uwp -pexample-wp -e 'select 1' wp >/dev/null 2>&1; then break; fi
  sleep 1
done
OUT=$(docker compose exec -T doorkeep doorkeep site create --name wordpress --origin "$URL")
KEY=$(printf '%s\n' "$OUT" | sed -n 's/.*site key[^:]*: *\([^ ]*\).*/\1/p')
SECRET=$(printf '%s\n' "$OUT" | sed -n 's/.*secret[^:]*: *\([^ ]*\).*/\1/p')
WP="docker compose run --rm -T cli wp"
$WP core is-installed 2>/dev/null || $WP core install --url="$URL" --title="doorkeep demo" \
  --admin_user=admin --admin_password='change me please' --admin_email=admin@example.com --skip-email
$WP plugin activate doorkeep
$WP option update doorkeep_settings --format=json "{\"public_url\":\"$URL/_dk\",\"verify_url\":\"http://doorkeep:8080\",\"site_key\":\"$KEY\",\"secret\":\"$SECRET\",\"fail_open\":0,\"login\":1,\"register\":1,\"lostpassword\":1,\"comments\":1,\"woocommerce\":0,\"compat\":\"\",\"trusted_proxies\":\"172.28.0.0/16\"}"
$WP doorkeep test
cat <<MSG

WordPress:  $URL/wp-login.php   (admin / change me please; change it)
Dashboard:  docker compose exec doorkeep doorkeep admin create --user ops
            then http://127.0.0.1:8081/admin/
MSG
