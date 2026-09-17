"""Domain expansion and parallel DNS-validation service."""

from concurrent.futures import ThreadPoolExecutor, as_completed

import tldextract

from quick_expand import check_dns, generate_candidates


TLD_PRIORITY = {
    "com": 1, "in": 2, "co.in": 3, "net": 4, "org": 5,
    "live": 6, "online": 7, "bet": 8, "io": 9, "co": 10,
}


def deduplicate_to_main_domains(domain_list: list[dict]) -> list[dict]:
    """Keep the preferred TLD for each domain-brand label."""
    brands: dict[str, dict] = {}
    for entry in domain_list:
        domain = entry["domain"]
        extracted = tldextract.extract(domain)
        brand = extracted.domain.lower()
        priority = TLD_PRIORITY.get(extracted.suffix.lower(), 50)
        if brand not in brands or priority < brands[brand]["priority"]:
            brands[brand] = {
                "domain": domain,
                "ip_address": entry.get("ip_address", ""),
                "priority": priority,
            }

    return [
        {"domain": info["domain"], "ip_address": info["ip_address"]}
        for _brand, info in sorted(brands.items())
    ]


def expand_domains(seeds: set[str], max_workers: int = 50) -> dict:
    """Generate, DNS-validate, and brand-deduplicate candidate domains."""
    candidates = generate_candidates(seeds)
    live: list[dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_dns, domain): domain for domain in candidates}
        for future in as_completed(futures):
            domain, ip_address = future.result()
            if ip_address:
                live.append({"domain": domain, "ip_address": ip_address})

    main_domains = deduplicate_to_main_domains(live)
    return {"candidates": candidates, "live": live, "main_domains": main_domains}
