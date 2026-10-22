=== doorkeep ===
Tags: spam, bot protection, captcha alternative, login security, privacy
Requires at least: 6.0
Tested up to: 6.8
Requires PHP: 8.0
Stable tag: 0.1.0
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
