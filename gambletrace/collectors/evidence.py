"""On-demand, read-only technical evidence collection for one domain.

The collector intentionally performs no discovery or monitoring on its own.
It is called by an analyst from an authorised case and returns structured
results that the persistence service records as one immutable observation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import timezone
import hashlib
import ipaddress
import json
import socket
import ssl
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup
import dns.resolver
from ipwhois import IPWhois
import requests

from gambletrace.services.content_fingerprinting import (
    ContentFingerprint,
    attach_favicon,
    fingerprint_html,
    same_origin_favicon_url,
)

USER_AGENT = "GambleTrace/0.1 authorised-evidence-collector"
DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA")


@dataclass(frozen=True)
class DnsRecord:
    """One DNS answer observed during collection."""

    record_type: str
    record_value: str
    ttl: int | None = None


@dataclass(frozen=True)
class RedirectHop:
    """One HTTP redirect hop in the observed redirect chain."""

    hop_number: int
    source_url: str
    status_code: int | None
    target_url: str


@dataclass
class HttpCapture:
    """HTTP response metadata and the in-memory body for evidence retention."""

    request_url: str = ""
    final_url: str = ""
    status_code: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    body_size_bytes: int = 0
    content_hash: str = ""
    body: bytes = field(default=b"", repr=False)
    content_fingerprint: ContentFingerprint = field(default_factory=ContentFingerprint)
    page_title: str = ""
    redirects: list[RedirectHop] = field(default_factory=list)
    error: str = ""


@dataclass
class RdapCapture:
    """RDAP/ASN metadata associated with a resolved public address."""

    ip_address: str
    asn_number: str = ""
    asn_description: str = ""
    provider_name: str = ""
    country_code: str = ""
    network_name: str = ""
    network_cidr: str = ""
    status: str = ""
    raw_response: dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass
class ScreenshotCapture:
    """Result of the optional Playwright screenshot attempt."""

    status: str = "NOT_CAPTURED"
    stored_path: str = ""
    response_status: int | None = None
    error: str = ""


@dataclass
class TlsCertificateCapture:
    """TLS certificate and handshake details observed on one resolved IP."""

    ip_address: str
    sha256_fingerprint: str = ""
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    subject_alt_names: list[str] = field(default_factory=list)
    tls_version: str = ""
    cipher_name: str = ""
    certificate_der: bytes = field(default=b"", repr=False)
    error: str = ""


@dataclass
class CollectionResult:
    """The complete technical result returned for a requested domain."""

    domain: str
    dns_records: list[DnsRecord] = field(default_factory=list)
    ip_addresses: list[tuple[str, str]] = field(default_factory=list)
    http: HttpCapture = field(default_factory=HttpCapture)
    rdap_records: list[RdapCapture] = field(default_factory=list)
    tls_certificates: list[TlsCertificateCapture] = field(default_factory=list)
    screenshot: ScreenshotCapture = field(default_factory=ScreenshotCapture)
    errors: list[str] = field(default_factory=list)


def _public_ip(address: str) -> bool:
    """Return true only for globally routable addresses."""
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def collect_dns(domain: str) -> tuple[list[DnsRecord], list[tuple[str, str]], list[str]]:
    """Resolve common DNS record types without raising collector-wide errors."""
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 4
    resolver.lifetime = 8
    records: list[DnsRecord] = []
    addresses: list[tuple[str, str]] = []
    errors: list[str] = []
    for record_type in DNS_RECORD_TYPES:
        try:
            answer = resolver.resolve(domain, record_type, raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as error:
            errors.append(f"DNS {record_type}: {error}")
            continue
        except Exception as error:  # Collector should retain partial evidence.
            errors.append(f"DNS {record_type}: {error}")
            continue
        if not answer.rrset:
            continue
        ttl = int(answer.rrset.ttl) if answer.rrset.ttl is not None else None
        for item in answer:
            value = item.to_text().strip()
            records.append(DnsRecord(record_type, value, ttl))
            if record_type in {"A", "AAAA"}:
                addresses.append((value, record_type))
    return records, addresses, errors


def _build_redirects(response: requests.Response) -> list[RedirectHop]:
    chain = [*response.history, response]
    redirects: list[RedirectHop] = []
    for index, hop in enumerate(response.history):
        location = hop.headers.get("Location", "")
        target_url = urljoin(hop.url, location) if location else chain[index + 1].url
        redirects.append(
            RedirectHop(index, hop.url, hop.status_code, target_url)
        )
    return redirects


def _collect_favicon(icon_url: str, headers: dict[str, str]) -> tuple[bytes, str]:
    """Fetch a bounded same-origin favicon for an otherwise successful page."""
    if not icon_url:
        return b"", ""
    try:
        response = requests.get(
            icon_url,
            headers=headers,
            timeout=(5, 10),
            allow_redirects=False,
            verify=True,
        )
        if not 200 <= response.status_code < 300:
            return b"", ""
        content = response.content
        if len(content) > 1024 * 1024:
            return b"", ""
        return content, response.headers.get("Content-Type", "application/octet-stream")
    except requests.RequestException:
        return b"", ""


def collect_http(domain: str) -> HttpCapture:
    """Collect HTTP metadata over HTTPS first, then HTTP as a fallback."""
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"}
    errors: list[str] = []
    for request_url in (f"https://{domain}", f"http://{domain}"):
        try:
            response = requests.get(
                request_url,
                headers=headers,
                timeout=(5, 15),
                allow_redirects=True,
                verify=True,
            )
            content = response.content
            content_type = response.headers.get("Content-Type", "")
            title = ""
            fingerprint = fingerprint_html(content, content_type)
            if "html" in content_type.lower():
                title = BeautifulSoup(content, "html.parser").title
                title = title.get_text(" ", strip=True) if title else ""
                icon_url = same_origin_favicon_url(response.url, content, content_type)
                favicon_bytes, favicon_mime_type = _collect_favicon(icon_url, headers)
                fingerprint = attach_favicon(
                    fingerprint, favicon_bytes, favicon_mime_type, icon_url
                )
            return HttpCapture(
                request_url=request_url,
                final_url=response.url,
                status_code=response.status_code,
                response_headers=dict(response.headers),
                content_type=content_type,
                body_size_bytes=len(content),
                content_hash=hashlib.sha256(content).hexdigest(),
                body=content,
                content_fingerprint=fingerprint,
                page_title=title,
                redirects=_build_redirects(response),
                error="",
            )
        except requests.RequestException as error:
            errors.append(f"{request_url}: {error}")
    return HttpCapture(request_url=f"https://{domain}", error="; ".join(errors))


def collect_rdap(ip_address: str) -> RdapCapture:
    """Collect RDAP metadata for one public IP address."""
    try:
        result = IPWhois(ip_address).lookup_rdap(depth=1)
        network = result.get("network") or {}
        return RdapCapture(
            ip_address=ip_address,
            asn_number=str(result.get("asn") or ""),
            asn_description=str(result.get("asn_description") or ""),
            provider_name=str(result.get("asn_description") or ""),
            country_code=str(result.get("asn_country_code") or ""),
            network_name=str(network.get("name") or ""),
            network_cidr=str(network.get("cidr") or ""),
            status=", ".join(str(value) for value in network.get("status", []) if value),
            raw_response=result,
        )
    except Exception as error:  # Network registries can be unavailable independently.
        return RdapCapture(ip_address=ip_address, error=str(error))


def _certificate_time(certificate, attribute: str) -> str:
    """Return a timezone-aware ISO timestamp across cryptography versions."""
    value = getattr(certificate, f"{attribute}_utc", None)
    if value is None:
        value = getattr(certificate, attribute)
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _parse_certificate(ip_address: str, certificate_der: bytes, tls_version: str, cipher_name: str) -> TlsCertificateCapture:
    """Parse a DER certificate without requiring it to be trusted."""
    try:
        from cryptography import x509

        certificate = x509.load_der_x509_certificate(certificate_der)
        try:
            extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            subject_alt_names = [str(name) for name in extension.value.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound:
            subject_alt_names = []
        return TlsCertificateCapture(
            ip_address=ip_address,
            sha256_fingerprint=hashlib.sha256(certificate_der).hexdigest(),
            subject=certificate.subject.rfc4514_string(),
            issuer=certificate.issuer.rfc4514_string(),
            serial_number=format(certificate.serial_number, "X"),
            not_before=_certificate_time(certificate, "not_valid_before"),
            not_after=_certificate_time(certificate, "not_valid_after"),
            subject_alt_names=subject_alt_names,
            tls_version=tls_version,
            cipher_name=cipher_name,
            certificate_der=certificate_der,
        )
    except Exception as error:
        return TlsCertificateCapture(
            ip_address=ip_address,
            sha256_fingerprint=hashlib.sha256(certificate_der).hexdigest(),
            tls_version=tls_version,
            cipher_name=cipher_name,
            certificate_der=certificate_der,
            error=f"Certificate parse failed: {error}",
        )


def collect_tls(domain: str, public_addresses: list[str]) -> list[TlsCertificateCapture]:
    """Collect TLS certificates through direct connections to known public IPs.

    Certificate verification is deliberately disabled because untrusted,
    expired, or self-signed certificates are themselves useful evidence. The
    TCP connection is made to the already-resolved public IP while preserving
    the domain as SNI, rather than resolving the hostname again.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    captures: list[TlsCertificateCapture] = []
    for ip_address in dict.fromkeys(public_addresses):
        try:
            with socket.create_connection((ip_address, 443), timeout=8) as connection:
                with context.wrap_socket(connection, server_hostname=domain) as secured:
                    certificate_der = secured.getpeercert(binary_form=True)
                    if not certificate_der:
                        captures.append(TlsCertificateCapture(ip_address=ip_address, error="Peer did not present a certificate"))
                        continue
                    cipher = secured.cipher()
                    captures.append(
                        _parse_certificate(
                            ip_address,
                            certificate_der,
                            secured.version() or "",
                            cipher[0] if cipher else "",
                        )
                    )
        except (OSError, ssl.SSLError) as error:
            captures.append(TlsCertificateCapture(ip_address=ip_address, error=str(error)))
    return captures


def collect_optional_screenshot(domain: str) -> ScreenshotCapture:
    """Capture a browser screenshot using the existing Playwright integration."""
    try:
        from gambletrace.collectors.browser import collect_liveness_screenshots

        results = asyncio.run(collect_liveness_screenshots([domain]))
        result = results[0] if results else {}
        path = str(result.get("screenshot_path") or "")
        response_status = result.get("response_status")
        if path:
            return ScreenshotCapture("CAPTURED", path, response_status)
        return ScreenshotCapture(
            "FAILED",
            "",
            response_status,
            str(result.get("error") or "Browser did not capture a screenshot"),
        )
    except Exception as error:
        return ScreenshotCapture("FAILED", error=str(error))


def collect_domain_evidence(domain: str, capture_screenshot: bool = False) -> CollectionResult:
    """Collect read-only technical evidence for an authorised case domain.

    Browser and HTTP collection are skipped unless DNS resolves to a public IP.
    This reduces risk from private-address DNS responses and rebinding targets.
    """
    records, addresses, errors = collect_dns(domain)
    public_addresses = [address for address, _ in addresses if _public_ip(address)]
    if not public_addresses:
        errors.append("No publicly routable resolved address; web collection skipped")
        return CollectionResult(
            domain=domain,
            dns_records=records,
            ip_addresses=addresses,
            errors=errors,
        )

    http = collect_http(domain)
    rdap_records = [collect_rdap(address) for address in dict.fromkeys(public_addresses)]
    tls_certificates = collect_tls(domain, public_addresses)
    screenshot = (
        collect_optional_screenshot(domain) if capture_screenshot else ScreenshotCapture()
    )
    if http.error:
        errors.append(http.error)
    if screenshot.error:
        errors.append(f"Screenshot: {screenshot.error}")
    errors.extend(f"RDAP {item.ip_address}: {item.error}" for item in rdap_records if item.error)
    errors.extend(f"TLS {item.ip_address}: {item.error}" for item in tls_certificates if item.error)
    return CollectionResult(
        domain=domain,
        dns_records=records,
        ip_addresses=addresses,
        http=http,
        rdap_records=rdap_records,
        tls_certificates=tls_certificates,
        screenshot=screenshot,
        errors=errors,
    )


def serialise_rdap(value: dict[str, Any]) -> str:
    """Produce a stable, safe JSON representation for a raw RDAP response."""
    return json.dumps(value, default=str, sort_keys=True)
