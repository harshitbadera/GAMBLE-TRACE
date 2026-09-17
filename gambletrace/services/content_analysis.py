"""Homepage content analysis and indicator extraction."""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


CREDENTIAL_PATTERNS = [
    (r'(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "API Key"),
    (r"(?:sk_live|pk_live|sk_test|pk_test)_[a-zA-Z0-9]{20,}", "Stripe Key"),
    (r"AIzaSy[a-zA-Z0-9_\-]{33}", "Google API Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r'(?:secret|password|passwd|pwd)\s*[:=]\s*["\']([^"\' ]{6,})["\']', "Password/Secret"),
    (r'(?:token|auth_token|access_token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']', "Auth Token"),
    (r'(?:mongodb|mysql|postgres|redis)://[^\s"\'>]+', "Database URL"),
    (r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}", "Bearer Token"),
]

BODY_GAMBLING_KEYWORDS = [
    "bet", "betting", "casino", "poker", "slot", "slots", "rummy", "satta", "matka",
    "teenpatti", "teen patti", "jackpot", "lottery", "sportsbook", "live casino",
    "live dealer", "blackjack", "roulette", "baccarat", "wager", "odds", "bookmaker",
]
BODY_INDIA_KEYWORDS = [
    "india", "indian", "inr", "₹", "rupee", "paytm", "phonepe", "google pay", "gpay",
    "upi", "imps", "neft", "net banking", "ipl", "cricket", "kabaddi", "hindi",
]
BODY_PAYMENT_KEYWORDS = [
    "upi", "paytm", "phonepe", "google pay", "gpay", "visa", "mastercard", "bitcoin",
    "btc", "usdt", "crypto", "skrill", "neteller", "bank transfer", "deposit", "withdraw", "payout",
]


def analyze_single_domain(domain: str) -> dict:
    """Fetch a homepage and extract content, indicator, and credential-scan results."""
    result = {
        "domain": domain, "http_status": "", "http_title": "", "body_size_bytes": 0,
        "body_size_kb": "", "gambling_keywords_found": "", "india_keywords_found": "",
        "payment_keywords_found": "", "hardcoded_credentials": "", "credential_count": 0,
        "is_live": "No",
    }
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"}
    body_text = ""
    for url in (f"https://{domain}", f"http://{domain}"):
        try:
            response = requests.get(url, headers=headers, timeout=12, verify=False, allow_redirects=True)
            result["http_status"] = str(response.status_code)
            if response.status_code < 400 or response.status_code in (401, 403):
                result["is_live"] = "Yes"
                body_text = response.text
                result["body_size_bytes"] = len(response.content)
                result["body_size_kb"] = f"{len(response.content) / 1024:.1f} KB"
                try:
                    from bs4 import BeautifulSoup
                    title_tag = BeautifulSoup(body_text, "html.parser").find("title")
                    if title_tag and title_tag.string:
                        result["http_title"] = title_tag.string.strip()[:200]
                except Exception:
                    title_match = re.search(r"<title[^>]*>([^<]+)</title>", body_text, re.IGNORECASE)
                    if title_match:
                        result["http_title"] = title_match.group(1).strip()[:200]
                break
        except Exception:
            continue

    if not body_text:
        return result

    body_lower = body_text.lower()
    for key, keywords in (
        ("gambling_keywords_found", BODY_GAMBLING_KEYWORDS),
        ("india_keywords_found", BODY_INDIA_KEYWORDS),
        ("payment_keywords_found", BODY_PAYMENT_KEYWORDS),
    ):
        matches = [keyword for keyword in keywords if keyword in body_lower]
        result[key] = "; ".join(matches) if matches else "None"

    credentials: list[str] = []
    for pattern, credential_type in CREDENTIAL_PATTERNS:
        for match in re.findall(pattern, body_text, re.IGNORECASE)[:3]:
            credentials.append(f"{credential_type}: {match}")
    result["hardcoded_credentials"] = "; ".join(credentials) if credentials else "None"
    result["credential_count"] = len(credentials)
    return result


def analyze_domains(domains: set[str], max_workers: int = 8) -> list[dict]:
    """Run bounded parallel content analysis and return domain-sorted results."""
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(analyze_single_domain, domain): domain for domain in sorted(domains)}
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda item: item["domain"])
