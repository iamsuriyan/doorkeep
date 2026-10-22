=== doorkeep ===
Tags: spam, bot protection, captcha alternative, login security, privacy
Requires at least: 6.0
Tested up to: 6.8
Requires PHP: 8.0
Stable tag: 0.2.0
License: Apache-2.0

Self-hosted, privacy-preserving bot protection. No third-party scripts, no tracking.

== Description ==

doorkeep scores each visitor invisibly (automation markers, browser consistency, behaviour, network) on a server you run, and only asks for proof of work or an accessible visual/audio check when unsure. This plugin protects login, registration, password reset, comments and WooCommerce checkout.

Marking a comment as spam reports it to doorkeep so your site's model learns from it.

== Installation ==

1. Run doorkeep and create a site: `doorkeep site create --name blog --origin https://your-site.example`.
2. Install this plugin and open Settings → doorkeep.
3. Enter the doorkeep URL, the site key and the secret. Choose what to protect.
4. Check with `wp doorkeep test`.
5. If WordPress runs behind a reverse proxy or CDN, list its addresses under "Trusted proxies" so doorkeep sees the visitor's real address (used when the site has strict IP binding on).

== WooCommerce ==

Both checkouts are protected. The classic (shortcode) checkout gets the usual hidden field. The block checkout has no form submit, so the plugin asks doorkeep for a token right before the order is placed and sends it with the Store API request as an `X-Doorkeep-Response` header; an order without a valid token is rejected with a notice.

== Changelog ==

= 0.2.0 =
* The snippet now loads on wp-login.php when only registration or lost password is protected.
* Trusted proxies setting for the visitor address behind a reverse proxy.
* WooCommerce block checkout protection.
