# IP blocklists and sharing

## Blocklists

`doorkeep ipdata update` (weekly by default) downloads plain-text IP
reputation lists. A visitor on one gets `IP_BLOCKLIST` (+25): evidence, not
proof, because public lists can include shared addresses (VPN exits, carrier
NAT). On its own it leads to a challenge at most.

The default is [FireHOL level 1](https://iplists.firehol.org/?ipset=firehol_level1),
which combines lists maintained to have no false positives (Spamhaus DROP and
EDROP, DShield, botnet command-and-control trackers). Private, shared and
documentation ranges in any list are ignored, so doorkeep behind a proxy or on
an intranet is never affected.

Add your own (any text list, one address or CIDR per line, `#` comments):

```yaml
ipdata_blocklists:
  - { name: firehol_level1, url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" }
  # CrowdSec: create a blocklist integration in the CrowdSec console; it gives
  # a URL with basic-auth credentials. Credentials are never written to logs
  # or sources.json.
  - { name: crowdsec, url: "https://USER:PASSWORD@admin.api.crowdsec.net/v1/integrations/ID/content" }
  # Another doorkeep's shared feed (below).
  - { name: partner, url: "https://dk.partner.example/v1/share/blocklist" }
```

or `DOORKEEP_IPDATA_BLOCKLISTS="name=url,name=url"`, or `none` to disable.
Removing a list from the configuration stops it applying immediately.

## Sharing (opt-in)

```yaml
share_blocklist: true
share_min_blocks: 10     # default
```

doorkeep then publishes, at `/v1/share/blocklist`, the networks (/24 IPv4,
/48 IPv6) it blocked at least `share_min_blocks` times in the last 24 hours.
Other doorkeep installs (or firewalls) subscribe by adding the URL as a
blocklist.

What is and is not shared:

- Only network prefixes, never addresses, fingerprints or anything about
  visitors.
- Only scored decisions: blocks caused by your own deny list are not shared.
- Counts live in memory for 24 hours and are never written to disk; in a
  cluster each node publishes its own view.

The feed publishes data derived from IP addresses of abusive traffic. Under
GDPR that is still personal data where a prefix identifies a person (rare for
a /24, possible for small networks); legitimate interest in network security
(Recital 49) usually covers it, but say so in your privacy notice before
enabling it.
