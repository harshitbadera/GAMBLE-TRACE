"""DNS, RDAP, and reverse-IP infrastructure analysis."""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import requests
import tldextract
from ipwhois import IPWhois

import config
from utils import is_valid_domain, normalize_domain


logger = logging.getLogger(__name__)

SKIP_ASNS = {
    "13335", "16509", "15169", "14618", "8075", "20940", "54113",
    "396982", "36492", "32934",
}

GAMBLING_FILTER_KEYWORDS = [
    "bet", "betting", "casino", "poker", "slot", "slots", "gambl", "rummy",
    "satta", "matka", "teenpatti", "jackpot", "lottery", "bingo", "wager",
    "punt", "bookmaker", "sportsbook", "odds", "spin", "roulette", "baccarat",
    "blackjack", "playwin", "winner", "lotto", "keno", "jeet", "baazi", "cric",
    "win", "play", "luck", "royal", "king", "mega", "super", "gold", "ace",
]


def lookup_single_domain(domain: str) -> dict:
    """Resolve a domain and enrich its first IPv4 address with RDAP data."""
    extracted = tldextract.extract(domain)
    main_domain = f"{extracted.domain}.{extracted.suffix}"
    result = {
        "domain": domain,
        "main_domain": main_domain,
        "ipv4_addresses": "",
        "ipv6_addresses": "",
        "hosting_provider": "",
        "country": "",
        "asn": "",
        "asn_description": "",
    }

    resolver = dns.resolver.Resolver()
    resolver.nameservers = config.DNS_NAMESERVERS
    resolver.timeout = 5
    resolver.lifetime = 8

    ipv4_list: list[str] = []
    try:
        answers = resolver.resolve(main_domain, "A", lifetime=8)
        ipv4_list = [answer.to_text() for answer in answers]
        result["ipv4_addresses"] = "; ".join(ipv4_list)
    except Exception:
        pass

    try:
        answers = resolver.resolve(main_domain, "AAAA", lifetime=8)
        result["ipv6_addresses"] = "; ".join(answer.to_text() for answer in answers)
    except Exception:
        pass

    if ipv4_list:
        try:
            rdap = IPWhois(ipv4_list[0]).lookup_rdap()
            network = rdap.get("network", {})
            result["hosting_provider"] = network.get("name") or ""
            result["country"] = network.get("country") or ""
            result["asn"] = rdap.get("asn") or ""
            result["asn_description"] = rdap.get("asn_description") or ""
        except Exception:
            pass
    return result


def lookup_domains(domains: set[str], max_workers: int = 10) -> list[dict]:
    """Run bounded parallel infrastructure lookups for the supplied domains."""
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(lookup_single_domain, domain): domain for domain in sorted(domains)}
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda item: item["domain"])


def non_cdn_ips(lookup_results: list[dict]) -> dict[str, dict]:
    """Collect unique IPv4s not attributed to the configured major CDN/cloud ASNs."""
    ip_to_info: dict[str, dict] = {}
    for result in lookup_results:
        asn = str(result.get("asn", "")).strip()
        if not asn or asn in SKIP_ASNS:
            continue
        for ip_address in result.get("ipv4_addresses", "").split(";"):
            ip_address = ip_address.strip()
            if ip_address and ip_address not in ip_to_info:
                ip_to_info[ip_address] = {
                    "hosting_provider": result.get("hosting_provider", ""),
                    "asn": asn,
                    "asn_description": result.get("asn_description", ""),
                    "country": result.get("country", ""),
                    "source_domain": result.get("domain", ""),
                }
    return ip_to_info


def reverse_ip_lookup(ip_address: str) -> list[str]:
    """Query HackerTarget's reverse-IP endpoint and return valid domain strings."""
    try:
        response = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip_address}",
            timeout=10,
        )
        if response.status_code != 200:
            return []
        text = response.text.strip()
        if text.startswith("error") or "API count" in text or not text:
            logger.warning("Reverse-IP lookup limit/error for %s: %s", ip_address, text[:80])
            return []
        return [
            domain for line in text.splitlines()
            if (domain := line.strip().lower()) and is_valid_domain(domain)
        ]
    except Exception as error:
        logger.error("Reverse-IP lookup failed for %s: %s", ip_address, error)
        return []


def run_reverse_ip_pivot(lookup_results: list[dict], input_domains: set[str]) -> list[dict]:
    """Discover new gambling-related domains on non-CDN infrastructure."""
    ip_to_info = non_cdn_ips(lookup_results)
    discovered: dict[str, dict] = {}
    for ip_address, info in ip_to_info.items():
        domains = reverse_ip_lookup(ip_address)
        logger.info("Reverse IP %s (%s): %s domains found", ip_address, info["source_domain"], len(domains))
        for domain in domains:
            normalized = normalize_domain(domain)
            if (
                not normalized
                or not is_valid_domain(normalized)
                or normalized in input_domains
                or normalized in discovered
                or not any(keyword in normalized for keyword in GAMBLING_FILTER_KEYWORDS)
            ):
                continue
            discovered[normalized] = {
                "domain": normalized,
                "found_on_ip": ip_address,
                "hosting_provider": info["hosting_provider"],
                "asn": info["asn"],
                "asn_description": info["asn_description"],
                "country": info["country"],
                "discovered_from": info["source_domain"],
            }
        time.sleep(1.5)
    return sorted(discovered.values(), key=lambda item: item["domain"])
