# fastblock

A PiHole blocklist aggregated from multiple reputable sources, with an allowlist that preserves affiliate links and email redirect domains so content creators retain revenue attribution.

## Using with PiHole

Add the following URL under **Group Management → Adlists**:

```
https://raw.githubusercontent.com/part-avocado/fastblock/master/hosts
```

Then run **Tools → Update Gravity**.

## Sources

| Source | Purpose |
|--------|---------|
| [HaGeZi Pro](https://github.com/hagezi/dns-blocklists) | Comprehensive ads, trackers, and malware |
| [AdGuard DNS Filter](https://github.com/AdguardTeam/AdGuardSDNSFilter) | Mobile ads + additional trackers |
| [OISD Big](https://oisd.nl) | Broad coverage, curated for low false positives |
| [URLhaus](https://urlhaus.abuse.ch) | Active malware distribution sites |

The `hosts` file is regenerated daily via GitHub Actions.

## Affiliate allowlist

Domains used by major affiliate networks are excluded from blocking, preserving click-through attribution:

- **Amazon Associates** — `amzn.to`, `assoc-amazon.com`
- **CJ Affiliate** — `anrdoezrs.net`, `dpbolvw.net`, `qksrv.net`, `tkqlhce.com`, and others
- **Impact** — `sjv.io`
- **Awin** — `awin1.com`, `awin.com`
- **Rakuten Advertising** — `linksynergy.com`
- **ShareASale** — `shareasale.com`
- **Skimlinks** — `skimlinks.com`, `go.skimresources.com`
- **Partnerize** — `prf.hn`
- **eBay Partner Network** — `rover.ebay.com`
- **Viglink / Sovrn Commerce** — `viglink.com`, `vig.link`

See `allowlist.txt` to add or remove entries.

## Building locally

Requires Python 3.12+, no external dependencies.

```bash
python3 build.py
```

On macOS, if you see SSL certificate errors, run:

```bash
python3 build.py --no-verify-ssl
```

Or install Python's certificates: open `/Applications/Python 3.x/Install Certificates.command`.

## Customizing

- **Add/remove sources**: edit `sources.txt`
- **Add/remove allowlisted domains**: edit `allowlist.txt`

## Output stats

~778,000 domains blocked (deduplicated across all sources, after allowlist).
