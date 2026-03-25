#!/usr/bin/env python3
"""
fastblock — aggregated DNS blocklist builder for PiHole.

Downloads multiple reputable blocklists, merges them, applies an allowlist
to preserve affiliate link domains, and writes a sorted hosts file.

Usage:
    python build.py

No external dependencies required (stdlib only).
"""

import argparse
import datetime
import logging
import pathlib
import re
import ssl
import sys
import urllib.error
import urllib.request

SCRIPT_DIR = pathlib.Path(__file__).parent
SOURCES_FILE = SCRIPT_DIR / "sources.txt"
ALLOWLIST_FILE = SCRIPT_DIR / "allowlist.txt"
OUTPUT_FILE = SCRIPT_DIR / "hosts"

REQUEST_TIMEOUT = 60  # seconds per download
USER_AGENT = "fastblock/1.0 (+https://github.com/part-avocado/fastblock)"

# Set at startup via --no-verify-ssl
_SSL_CONTEXT: ssl.SSLContext | None = None

# RFC-1123 hostname label, requires at least one dot (rejects bare hostnames and IPs)
_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$"
)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

_SKIP_DOMAINS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "ip6-localnet",
        "ip6-mcastprefix",
        "ip6-allnodes",
        "ip6-allrouters",
        "ip6-allhosts",
        "0.0.0.0",
        "127.0.0.1",
        "::1",
    }
)


def load_sources(path: pathlib.Path) -> list[str]:
    if not path.exists():
        sys.exit(f"ERROR: {path} not found")
    urls = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


def load_allowlist(path: pathlib.Path) -> frozenset[str]:
    if not path.exists():
        logging.warning("Allowlist file not found: %s — proceeding without it", path)
        return frozenset()
    domains = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            domains.add(line)
    logging.info("Allowlist loaded: %d entries", len(domains))
    return frozenset(domains)


def fetch_source(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=_SSL_CONTEXT) as resp:
            data = resp.read()
        return data.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        logging.warning("HTTP %s fetching %s — skipping", exc.code, url)
    except urllib.error.URLError as exc:
        logging.warning("URL error fetching %s: %s — skipping", url, exc.reason)
    except Exception as exc:  # noqa: BLE001
        logging.warning("Unexpected error fetching %s: %s — skipping", url, exc)
    return ""


def _is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    if domain in _SKIP_DOMAINS:
        return False
    if _IP_RE.match(domain):
        return False
    return bool(_DOMAIN_RE.match(domain))


def detect_format(text: str) -> str:
    """Return 'adblock' if the text looks like an adblock filter list, else 'hosts'."""
    checked = 0
    adblock_count = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if "||" in line:
            adblock_count += 1
        checked += 1
        if checked >= 50:
            break
    if checked == 0:
        return "hosts"
    return "adblock" if (adblock_count / checked) > 0.2 else "hosts"


def parse_hosts_format(text: str) -> set[str]:
    domains: set[str] = set()
    for line in text.splitlines():
        # Strip inline comments
        line = line.split("#")[0].strip().lower()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip, domain = parts[0], parts[1]
        if ip not in ("0.0.0.0", "127.0.0.1"):
            continue
        if _is_valid_domain(domain):
            domains.add(domain)
    return domains


def parse_adblock_format(text: str) -> set[str]:
    domains: set[str] = set()
    # Match ||domain^ at start of line (DNS-level domain rules only)
    rule_re = re.compile(r"^\|\|([^/^*@|$,\s]+)\^")
    for line in text.splitlines():
        line = line.strip().lower()
        if not line:
            continue
        # Skip comments and metadata
        if line[0] in ("!", "#", "["):
            continue
        # Skip allowlist/exception rules
        if line.startswith("@@"):
            continue
        # Skip cosmetic/element-hiding rules
        if any(marker in line for marker in ("##", "#@#", "#?#", "#$#")):
            continue
        # Skip path, regex, or wildcard rules
        if "/" in line or "*" in line:
            continue
        m = rule_re.match(line)
        if not m:
            continue
        domain = m.group(1)
        if _is_valid_domain(domain):
            domains.add(domain)
    return domains


def parse_source(text: str) -> set[str]:
    fmt = detect_format(text)
    if fmt == "adblock":
        return parse_adblock_format(text)
    return parse_hosts_format(text)


def apply_allowlist(domains: set[str], allowlist: frozenset[str]) -> set[str]:
    # Support both exact matches (example.com) and suffix matches (*.example.com).
    # A blocked domain is removed if it equals an allowlist entry OR ends with .{entry}.
    result = set()
    removed = 0
    for domain in domains:
        allowed = False
        for entry in allowlist:
            if domain == entry or domain.endswith("." + entry):
                allowed = True
                break
        if allowed:
            removed += 1
        else:
            result.add(domain)
    if removed:
        logging.info("Allowlist removed %d domain(s)", removed)
    return result


def build_header(sources: list[str], domain_count: int) -> str:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    source_lines = "\n".join(f"#   {url}" for url in sources)
    return f"""\
#################################################################
# fastblock - aggregated DNS blocklist for PiHole
# https://github.com/part-avocado/fastblock
#
# Generated : {now}
# Sources   : {len(sources)}
# Domains   : {domain_count:,} (after allowlist)
#
# To use with PiHole, add this URL under Group Management > Adlists:
#   https://raw.githubusercontent.com/part-avocado/fastblock/main/hosts
#
# Sources used:
{source_lines}
#
# Affiliate and redirect domains are preserved via allowlist.txt
# Edit sources.txt or allowlist.txt, then run build.py to rebuild.
#################################################################

"""


def write_output(
    path: pathlib.Path, domains: set[str], header: str, sources: list[str]
) -> None:
    lines = [f"0.0.0.0 {d}" for d in sorted(domains)]
    content = header + "\n".join(lines) + "\n"
    path.write_text(content, encoding="utf-8")


def main() -> None:
    global _SSL_CONTEXT

    parser = argparse.ArgumentParser(description="Build fastblock hosts file")
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification (useful on macOS without certifi)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.no_verify_ssl:
        _SSL_CONTEXT = ssl._create_unverified_context()  # noqa: SLF001
        logging.warning("SSL verification disabled — only use this locally")

    sources = load_sources(SOURCES_FILE)
    allowlist = load_allowlist(ALLOWLIST_FILE)

    all_domains: set[str] = set()

    for url in sources:
        logging.info("Fetching %s", url)
        text = fetch_source(url)
        if not text:
            continue
        domains = parse_source(text)
        logging.info("  -> %d domains parsed", len(domains))
        all_domains |= domains

    logging.info("Total before allowlist: %d", len(all_domains))
    all_domains = apply_allowlist(all_domains, allowlist)
    logging.info("Total after allowlist : %d", len(all_domains))

    header = build_header(sources, len(all_domains))
    write_output(OUTPUT_FILE, all_domains, header, sources)
    logging.info("Written: %s", OUTPUT_FILE)


if __name__ == "__main__":
    main()
