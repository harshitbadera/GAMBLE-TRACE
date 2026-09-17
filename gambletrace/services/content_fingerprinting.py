"""Deterministic HTML, visible-text, favicon, and indicator fingerprints."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Iterable
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup, Comment


GAMBLING_INDICATORS = (
    "betting", "casino", "sportsbook", "bookmaker", "teen patti", "teenpatti",
    "rummy", "slots", "poker", "roulette", "blackjack", "baccarat", "wager",
    "odds", "jackpot", "live dealer",
)
PAYMENT_INDICATORS = (
    "upi", "paytm", "phonepe", "google pay", "net banking", "bank transfer",
    "deposit", "withdraw", "payout", "bitcoin", "usdt", "crypto", "visa",
    "mastercard", "skrill", "neteller",
)
INDIA_INDICATORS = (
    "india", "indian", "inr", "rupee", "ipl", "cricket", "kabaddi", "hindi",
    "imps", "neft", "rtgs",
)


@dataclass
class ContentFingerprint:
    """Evidence-safe fingerprints and explainable indicators from one response."""

    normalized_html_hash: str = ""
    visible_text_hash: str = ""
    favicon_hash: str = ""
    favicon_bytes: bytes = field(default=b"", repr=False)
    favicon_mime_type: str = ""
    favicon_source_url: str = ""
    gambling_indicators: dict[str, int] = field(default_factory=dict)
    payment_indicators: dict[str, int] = field(default_factory=dict)
    india_indicators: dict[str, int] = field(default_factory=dict)


def _normalise_space(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _indicator_counts(text: str, indicators: Iterable[str]) -> dict[str, int]:
    lowered = text.casefold()
    return {
        indicator: lowered.count(indicator.casefold())
        for indicator in indicators
        if lowered.count(indicator.casefold())
    }


def fingerprint_html(content: bytes, content_type: str) -> ContentFingerprint:
    """Create stable hashes after removing non-visible and volatile markup."""
    if not content or "html" not in content_type.lower():
        return ContentFingerprint()
    soup = BeautifulSoup(content, "html.parser")
    for node in soup.find_all(string=lambda value: isinstance(value, Comment)):
        node.extract()
    for tag in soup.find_all(["script", "style", "noscript", "template"]):
        tag.decompose()
    for tag in soup.find_all(True):
        for attribute in list(tag.attrs):
            if attribute == "id" or attribute == "nonce" or attribute.startswith("data-"):
                del tag.attrs[attribute]
        tag.attrs = dict(sorted(tag.attrs.items()))
    normalised_html = _normalise_space(str(soup))
    visible_text = _normalise_space(soup.get_text(" ", strip=True))
    indicator_text = f"{visible_text} {_normalise_space(soup.title.get_text(' ', strip=True)) if soup.title else ''}"
    return ContentFingerprint(
        normalized_html_hash=hashlib.sha256(normalised_html.encode("utf-8")).hexdigest(),
        visible_text_hash=hashlib.sha256(visible_text.encode("utf-8")).hexdigest(),
        gambling_indicators=_indicator_counts(indicator_text, GAMBLING_INDICATORS),
        payment_indicators=_indicator_counts(indicator_text, PAYMENT_INDICATORS),
        india_indicators=_indicator_counts(indicator_text, INDIA_INDICATORS),
    )


def same_origin_favicon_url(page_url: str, content: bytes, content_type: str) -> str:
    """Return a same-origin favicon candidate, avoiding arbitrary third-party fetches."""
    parsed_page = urlsplit(page_url)
    if parsed_page.scheme not in {"http", "https"} or not parsed_page.netloc:
        return ""
    candidate = "/favicon.ico"
    if content and "html" in content_type.lower():
        soup = BeautifulSoup(content, "html.parser")
        for link in soup.find_all("link"):
            relation = " ".join(link.get("rel") or []).lower()
            href = link.get("href")
            if href and "icon" in relation:
                candidate = href
                break
    icon_url = urljoin(page_url, candidate)
    parsed_icon = urlsplit(icon_url)
    if parsed_icon.scheme not in {"http", "https"} or parsed_icon.netloc != parsed_page.netloc:
        return ""
    return icon_url


def attach_favicon(
    fingerprint: ContentFingerprint,
    favicon_bytes: bytes,
    favicon_mime_type: str,
    favicon_source_url: str,
) -> ContentFingerprint:
    """Attach a downloaded favicon to an HTML fingerprint without mutation surprises."""
    if not favicon_bytes:
        return fingerprint
    return ContentFingerprint(
        normalized_html_hash=fingerprint.normalized_html_hash,
        visible_text_hash=fingerprint.visible_text_hash,
        favicon_hash=hashlib.sha256(favicon_bytes).hexdigest(),
        favicon_bytes=favicon_bytes,
        favicon_mime_type=favicon_mime_type,
        favicon_source_url=favicon_source_url,
        gambling_indicators=fingerprint.gambling_indicators,
        payment_indicators=fingerprint.payment_indicators,
        india_indicators=fingerprint.india_indicators,
    )
