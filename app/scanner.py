from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
import base64
from collections import defaultdict, deque
from datetime import datetime, timezone
from functools import lru_cache
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from app.ml_model import classify_url
from app.scoring import score_scan
from app.xgb_model import classify_url_xgboost

MAX_HTML_BYTES = 1_000_000
MAX_REDIRECTS = 5
NETWORK_TIMEOUT = 4
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "work", "support"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
KEYWORDS = {"login", "verify", "secure", "update", "account", "password", "signin", "wallet"}
MULTI_LABEL_SUFFIXES = {
    "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk",
    "com.au", "edu.au", "gov.au", "net.au", "org.au",
    "co.in", "com.in", "firm.in", "gen.in", "ind.in", "net.in", "org.in",
    "co.jp", "ne.jp", "or.jp",
    "com.br", "net.br", "org.br",
    "com.cn", "net.cn", "org.cn",
    "com.hk", "org.hk", "com.mx", "org.mx",
    "co.nz", "net.nz", "org.nz",
    "com.sg", "net.sg", "org.sg",
    "co.za", "org.za",
}
BRANDS = {
    "amazon": {"amazon.com"},
    "apple": {"apple.com"},
    "facebook": {"facebook.com", "fb.com"},
    "google": {"google.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "netflix": {"netflix.com"},
    "paypal": {"paypal.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi"},
    "hdfc": {"hdfcbank.com"},
    "paytm": {"paytm.com"},
    "irctc": {"irctc.co.in"},
    "aadhaar": {"uidai.gov.in"},
}


class ScanError(ValueError):
    """An invalid URL or a target that must not be contacted."""


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip("[]")).is_global
    except ValueError:
        return False


def normalize_url(raw_url: str) -> str:
    value = raw_url.strip()
    if not value:
        raise ScanError("Enter a URL to scan.")
    if any(ord(char) < 32 or char.isspace() for char in value):
        raise ScanError("The URL must not contain spaces or control characters.")
    if "://" not in value:
        value = "https://" + value
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise ScanError("The URL has an invalid host or port.") from exc
    if parts.scheme.lower() not in {"http", "https"}:
        raise ScanError("Only HTTP and HTTPS URLs can be scanned.")
    if not parts.hostname or parts.username is not None or parts.password is not None:
        raise ScanError("Enter a valid website URL without embedded credentials.")
    host = parts.hostname.rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScanError("The URL contains an invalid domain name.") from exc
    if len(host) > 253 or not host:
        raise ScanError("The URL contains an invalid domain name.")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
        raise ScanError("Local and reserved hostnames cannot be scanned.")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        # Allow static analysis of private/loopback addresses, but block network requests later.
        pass
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and not ((parts.scheme.lower() == "https" and port == 443) or (parts.scheme.lower() == "http" and port == 80)):
        netloc += f":{port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


@lru_cache(maxsize=2048)
def resolve_public(host: str, port: int) -> list[str]:
    host = (host or "").strip("[]")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        return [str(literal)] if literal.is_global else []
    try:
        addresses = list({
            item[4][0]
            for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        })
    except OSError:
        return []
    public = []
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError:
            continue
        if parsed.is_global:
            public.append(str(parsed))
    return public


def _connect(url: str) -> tuple[http.client.HTTPConnection, str]:
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    addresses = resolve_public(host, port)
    if not addresses:
        raise ScanError("Network checks were skipped because the host is unresolved, private, or reserved.")
    last_error: OSError | None = None
    for address in addresses:
        try:
            raw_socket = socket.create_connection((address, port), timeout=NETWORK_TIMEOUT)
            if parts.scheme == "https":
                try:
                    context = ssl.create_default_context()
                    raw_socket = context.wrap_socket(raw_socket, server_hostname=host)
                except (OSError, ssl.SSLError, ValueError):
                    raw_socket.close()
                    raise
                connection: http.client.HTTPConnection = http.client.HTTPSConnection(host, port, timeout=NETWORK_TIMEOUT)
            else:
                connection = http.client.HTTPConnection(host, port, timeout=NETWORK_TIMEOUT)
            connection.sock = raw_socket
            return connection, host
        except (OSError, ssl.SSLError) as exc:
            last_error = exc
    raise OSError(f"Could not connect to the public website: {last_error}")


def safe_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    max_bytes: int = MAX_HTML_BYTES,
    follow_redirects: bool = True,
    read_body: bool = True,
) -> tuple[int, dict[str, str], bytes, list[str]]:
    current = normalize_url(url)
    chain = [current]
    for hop in range(MAX_REDIRECTS + 1):
        connection, host = _connect(current)
        try:
            parts = urlsplit(current)
            target = urlunsplit(("", "", parts.path or "/", parts.query, ""))
            request_headers = {
                "Host": f"[{host}]" if ":" in host else host,
                "User-Agent": "PhishLens/1.0 (+URL safety scanner)",
                "Accept": "text/html,application/json;q=0.9,*/*;q=0.5",
                "Connection": "close",
            }
            if parts.port is not None and not (
                (parts.scheme == "https" and parts.port == 443)
                or (parts.scheme == "http" and parts.port == 80)
            ):
                request_headers["Host"] += f":{parts.port}"
            if headers:
                request_headers.update(headers)
            connection.request(method, target, body=body, headers=request_headers)
            response = connection.getresponse()
            response_headers = {key.lower(): value for key, value in response.getheaders()}
            if response.status in {301, 302, 303, 307, 308} and response_headers.get("location") and follow_redirects:
                if hop >= MAX_REDIRECTS:
                    raise OSError("The website exceeded the redirect limit.")
                current = normalize_url(urljoin(current, response_headers["location"]))
                chain.append(current)
                method, body = ("GET", None) if response.status == 303 or (response.status in {301, 302} and method != "GET") else (method, body)
                continue
            content = b""
            if read_body:
                content_length = response_headers.get("content-length")
                if content_length and content_length.isdigit() and int(content_length) > max_bytes:
                    raise OSError("The website response is larger than the scan limit.")
                content = response.read(max_bytes + 1)
                if len(content) > max_bytes:
                    raise OSError("The website response is larger than the scan limit.")
            return response.status, response_headers, content, chain
        finally:
            connection.close()
    raise OSError("The website exceeded the redirect limit.")


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.in_title = False
        self.password_fields = 0
        self.password_form_actions: list[str] = []
        self.forms: list[str] = []
        self.current_form: str | None = None
        self.hidden_iframes = 0
        self.external_links: set[str] = set()
        self.favicon: str | None = None
        self.page_host = ""

    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        attrs = {key.lower(): value or "" for key, value in attrs_list}
        if tag == "title":
            self.in_title = True
        elif tag == "input" and attrs.get("type", "").lower() == "password":
            self.password_fields += 1
            if self.current_form is not None:
                self.password_form_actions.append(self.current_form)
        elif tag == "form":
            self.current_form = attrs.get("action", "")
            self.forms.append(self.current_form)
        elif tag == "iframe":
            style = attrs.get("style", "").replace(" ", "").lower()
            if "hidden" in attrs or "display:none" in style or "visibility:hidden" in style:
                self.hidden_iframes += 1
        elif tag == "a" and attrs.get("href"):
            try:
                target_host = (urlsplit(urljoin("https://" + self.page_host, attrs["href"])).hostname or "").lower()
                if target_host and target_host != self.page_host and not target_host.endswith("." + self.page_host):
                    self.external_links.add(target_host)
            except ValueError:
                pass
        elif tag == "link" and "icon" in attrs.get("rel", "").lower() and attrs.get("href"):
            self.favicon = attrs["href"]

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False
        elif tag == "form":
            self.current_form = None

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data.strip())


def _check(name: str, title: str, triggered: bool, explanation: str, weight: int) -> dict[str, Any]:
    return {"name": name, "title": title, "triggered": triggered, "explanation": explanation, "weight": weight}


def _url_checks(url: str, host: str, domain: str) -> list[dict[str, Any]]:
    parts = urlsplit(url)
    labels = host.split(".")
    tld = labels[-1] if labels else ""
    lower = url.lower()
    checks = [
        _check("url_length", "Unusually long URL", len(url) > 75, f"The URL is {len(url)} characters long; long URLs can conceal their real destination.", 8),
        _check("at_symbol", "Credential-style @ symbol", "@" in parts.netloc, "An @ symbol in the address can make a misleading URL appear to belong to a trusted site.", 24),
        _check("ip_host", "IP address used as host", _is_ip(host), "The website uses a numeric IP address instead of a recognizable domain.", 24),
        _check("many_subdomains", "Many subdomains", len(labels) > 4, f"The hostname contains {max(0, len(labels) - 2)} subdomain labels.", 13),
        _check("hyphens", "Excessive domain hyphens", host.count("-") >= 3, "Several hyphens in the hostname can imitate legitimate brand domains.", 10),
        _check("suspicious_tld", "Higher-risk top-level domain", tld in SUSPICIOUS_TLDS, f"The .{tld} top-level domain is frequently used in disposable or deceptive campaigns.", 11),
        _check("punycode", "Encoded internationalized domain", "xn--" in host, "The domain contains punycode, which may be used to imitate another character set.", 15),
        _check("shortener", "URL shortener", domain in SHORTENERS, "The shortened URL hides its final destination until it is followed.", 12),
    ]
    matched_keywords = sorted(keyword for keyword in KEYWORDS if re.search(rf"(?<![a-z]){re.escape(keyword)}(?![a-z])", lower))
    checks.append(_check(
        "sensitive_keywords", "Sensitive account-related words", bool(matched_keywords),
        f"The URL contains: {', '.join(matched_keywords)}. These words are common in credential-stealing lures but are not proof of abuse.",
        8 if len(matched_keywords) < 3 else 13,
    ))
    mismatched_brands = [
        brand for brand, official_domains in BRANDS.items()
        if re.search(rf"(?<![a-z0-9]){brand}(?![a-z0-9])", parts.netloc.lower() + parts.path.lower())
        and not any(domain == official or domain.endswith("." + official) for official in official_domains)
    ]
    checks.append(_check(
        "brand_impersonation", "Brand name outside its official domain", bool(mismatched_brands),
        f"The URL mentions {', '.join(mismatched_brands)} without using that brand's official domain.",
        40,
    ))
    return checks


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _registrable_domain(host: str) -> str:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        labels = host.split(".")
        if len(labels) > 2 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:]) if len(labels) > 1 else host


def _domain_details(host: str, scheme: str, address: str | None, port: int) -> dict[str, Any]:
    details: dict[str, Any] = {
        "domain": _registrable_domain(host),
        "dns": {"status": "resolved" if address else "unresolved", "ip": address},
        "age_days": None,
        "registered_on": None,
        "ssl": {"valid": None, "issuer": None, "expires_on": None},
    }
    if scheme == "https" and address:
        try:
            tls_socket = _tls_socket(host, address, port)
            try:
                cert = tls_socket.getpeercert()
            finally:
                tls_socket.close()
            issuer_values = [value for group in cert.get("issuer", ()) for _, value in group]
            expires = cert.get("notAfter")
            details["ssl"] = {
                "valid": True,
                "issuer": ", ".join(issuer_values[-2:]) or "Trusted certificate",
                "expires_on": _format_cert_date(expires),
            }
        except (OSError, ssl.SSLError, ValueError):
            details["ssl"] = {"valid": False, "issuer": None, "expires_on": None}
    if not address:
        details["dns"] = {"status": "warning", "ip": None, "warning": "DNS resolution failed or was skipped for a non-public address."}
    details.update(_rdap_details(details["domain"]))
    return details


def _tls_socket(host: str, address: str, port: int) -> ssl.SSLSocket:
    raw = socket.create_connection((address, port), timeout=NETWORK_TIMEOUT)
    try:
        return ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    except (OSError, ssl.SSLError, ValueError):
        raw.close()
        raise


def _format_cert_date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).date().isoformat()
    except ValueError:
        return value


@lru_cache(maxsize=512)
def _rdap_details(domain: str) -> dict[str, Any]:
    try:
        status, _, content, _ = safe_request(
            f"https://rdap.org/domain/{quote(domain, safe='.-')}",
            headers={"Accept": "application/rdap+json, application/json"},
            max_bytes=200_000,
        )
        if status != 200:
            return {}
        data = json.loads(content)
        registered = next(
            (event.get("eventDate") for event in data.get("events", [])
             if event.get("eventAction", "").lower() in {"registration", "registered", "creation"}),
            None,
        )
        if not registered:
            return {}
        created = parsedate_to_datetime(registered) if "," in registered else datetime.fromisoformat(registered.replace("Z", "+00:00"))
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return {"registered_on": created.date().isoformat(), "age_days": max(0, (datetime.now(timezone.utc) - created).days)}
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, ScanError):
        return {}


def _tool_url(value: str) -> tuple[str, str, str]:
    url = normalize_url(value)
    host = urlsplit(url).hostname or ""
    return url, host, _registrable_domain(host)


def check_ssl(value: str) -> dict[str, Any]:
    _, host, domain = _tool_url(value)
    addresses = resolve_public(host, 443)
    if not addresses:
        return {"status": "skipped", "domain": domain, "valid": False, "warning": "DNS was unavailable or the target is private/reserved; network verification was skipped."}
    try:
        tls_socket = _tls_socket(host, addresses[0], 443)
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {"status": "invalid", "domain": domain, "valid": False, "error": str(exc)}
    try:
        cert = tls_socket.getpeercert()
    finally:
        tls_socket.close()
    issuer_values = [value for group in cert.get("issuer", ()) for _, value in group]
    expires_on = _format_cert_date(cert.get("notAfter"))
    return {
        "status": "checked",
        "domain": domain,
        "valid": True,
        "issuer": ", ".join(issuer_values[-2:]) or "Trusted certificate",
        "expires_on": expires_on,
    }


def lookup_dns(value: str) -> dict[str, Any]:
    _, host, domain = _tool_url(value)
    addresses = resolve_public(host, 443)
    if not addresses:
        return {"status": "unresolved", "domain": domain, "warning": "DNS resolution failed or the target is not a public address.", "records": []}
    return {
        "status": "resolved",
        "domain": domain,
        "records": [
            {"type": "AAAA" if ipaddress.ip_address(address).version == 6 else "A", "value": address}
            for address in addresses
        ],
    }


def lookup_website_age(value: str) -> dict[str, Any]:
    _, host, domain = _tool_url(value)
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        details = _rdap_details(domain)
    else:
        return {"status": "not_applicable", "domain": domain, "age_days": None, "registered_on": None}
    return {
        "status": "available" if details.get("age_days") is not None else "unavailable",
        "domain": domain,
        "age_days": details.get("age_days"),
        "registered_on": details.get("registered_on"),
    }


def expand_link(value: str) -> dict[str, Any]:
    url, _, _ = _tool_url(value)
    status, _, _, chain = safe_request(url, read_body=False)
    return {"status": status, "original_url": url, "final_url": chain[-1], "redirect_chain": chain}


def check_ip_reputation(value: str) -> dict[str, Any]:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ScanError("Enter a valid public IPv4 or IPv6 address.") from exc
    if not address.is_global:
        raise ScanError("IP reputation checks are only available for public IP addresses.")
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {
            "status": "not_configured",
            "ip": str(address),
            "message": "Configure VIRUSTOTAL_API_KEY to check IP reputation.",
        }
    try:
        status, _, content, _ = safe_request(
            f"https://www.virustotal.com/api/v3/ip_addresses/{quote(str(address), safe=':')}",
            headers={"x-apikey": api_key},
            max_bytes=200_000,
            follow_redirects=False,
        )
        if status != 200:
            return {"status": "unavailable", "ip": str(address), "message": f"VirusTotal returned HTTP {status}."}
        data = json.loads(content)
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        return {
            "status": "checked",
            "ip": str(address),
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": int(stats.get("harmless", 0)),
            "verdict": "flagged" if malicious + suspicious else "no detections",
        }
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, ScanError) as exc:
        return {"status": "unavailable", "ip": str(address), "message": str(exc)}


def _page_details(url: str, host: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    status, headers, content, chain = safe_request(url)
    is_html = "html" in headers.get("content-type", "").lower() or not headers.get("content-type")
    details: dict[str, Any] = {
        "status_code": status,
        "redirect_chain": chain,
        "title": None,
        "login_form": None,
        "forms_cross_domain": None,
        "hidden_iframes": None,
        "external_links": None,
        "favicon": None,
    }
    checks = [
        _check("redirects", "Multiple redirects", len(chain) > 2, f"The request passed through {len(chain) - 1} redirects before reaching its destination.", 8),
    ]
    if not is_html:
        return details, checks
    final_url = chain[-1]
    final_host = (urlsplit(final_url).hostname or host).lower()
    parser = PageParser()
    parser.page_host = final_host
    charset_match = re.search(r"charset\s*=\s*[\"']?([^;\"'\s]+)", headers.get("content-type", ""), re.IGNORECASE)
    charset = charset_match.group(1) if charset_match else "utf-8"
    try:
        content_text = content.decode(charset, errors="replace")
    except LookupError:
        content_text = content.decode("utf-8", errors="replace")
    parser.feed(content_text)
    title = " ".join(part for part in parser.title_parts if part) or None
    cross_domain = False
    for action in parser.forms:
        if action:
            action_host = (urlsplit(urljoin(final_url, action)).hostname or "").lower()
            if action_host and _registrable_domain(action_host) != _registrable_domain(final_host):
                cross_domain = True
    credential_exfiltration = False
    for action in parser.password_form_actions:
        if action:
            action_host = (urlsplit(urljoin(final_url, action)).hostname or "").lower()
            if action_host and _registrable_domain(action_host) != _registrable_domain(final_host):
                credential_exfiltration = True
    details.update({
        "title": title,
        "login_form": parser.password_fields > 0,
        "forms_cross_domain": cross_domain,
        "hidden_iframes": parser.hidden_iframes,
        "external_links": len(parser.external_links),
        "favicon": urljoin(final_url, parser.favicon) if parser.favicon else None,
    })
    try:
        favicon_host = (urlsplit(details["favicon"]).hostname or "").lower() if details["favicon"] else ""
    except ValueError:
        favicon_host = ""
    domain = _registrable_domain(final_host)
    page_brands = [
        brand for brand, official_domains in BRANDS.items()
        if re.search(rf"(?<![a-z0-9]){brand}(?![a-z0-9])", (title or "").lower() + " " + favicon_host)
        and not any(domain == official or domain.endswith("." + official) for official in official_domains)
    ]
    details["favicon_host"] = favicon_host or None
    checks.extend([
        _check("password_form", "Password field detected", parser.password_fields > 0, "The page contains a password input. Login pages are common phishing targets; this alone is not proof of phishing.", 3),
        _check("cross_domain_form", "Form submits to another domain", cross_domain, "At least one form sends submitted data to a different domain.", 22),
        _check("credential_exfiltration", "Password form submits to another domain", credential_exfiltration, "A password form submits credentials to a different registered domain.", 70),
        _check("hidden_iframe", "Hidden iframe detected", parser.hidden_iframes > 0, "The page contains an iframe hidden from visitors, which can conceal content or behavior.", 14),
        _check("external_links", "Many external link destinations", len(parser.external_links) > 25, f"The page links to {len(parser.external_links)} distinct external domains.", 7),
        _check("page_brand_mismatch", "Page branding does not match its domain", bool(page_brands), f"The page title or favicon references {', '.join(page_brands)} while the website uses {domain}.", 18),
    ])
    return details, checks


def _feed_results(url: str, domain: str) -> dict[str, Any]:
    feeds: dict[str, Any] = {}
    openphish_path = Path(os.getenv("OPENPHISH_FEED_FILE", "data/known_phishing_domains.txt"))
    if not openphish_path.is_absolute():
        openphish_path = Path(__file__).resolve().parent.parent / openphish_path
    try:
        with openphish_path.open(encoding="utf-8") as feed:
            entries = {line.strip().lower() for line in feed if line.strip() and not line.lstrip().startswith("#")}
        matched = any(
            entry == url.lower() or domain == entry or domain.endswith("." + entry)
            for entry in entries
        )
        feeds["local_list"] = {"status": "checked", "matched": matched}
    except FileNotFoundError:
        feeds["local_list"] = {"status": "unavailable", "matched": False}
    checks: list[dict[str, Any]] = [
        _check("local_threat_list", "Listed in local threat feed", feeds["local_list"]["matched"], "This URL or domain appears in the configured local phishing list.", 60)
    ]
    google_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if google_key:
        try:
            request_body = json.dumps({
                "client": {"clientId": "phishlens", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}],
                },
            }).encode()
            status, _, response, _ = safe_request(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + quote(google_key, safe=""),
                method="POST", body=request_body, headers={"Content-Type": "application/json"}, max_bytes=100_000, follow_redirects=False,
            )
            matched = status == 200 and bool(json.loads(response).get("matches"))
            feeds["google_safe_browsing"] = {"status": "checked" if status == 200 else "unavailable", "matched": matched}
        except (OSError, ValueError, json.JSONDecodeError, ScanError):
            feeds["google_safe_browsing"] = {"status": "unavailable", "matched": False}
        checks.append(_check("google_safe_browsing", "Google Safe Browsing match", feeds["google_safe_browsing"]["matched"], "Google Safe Browsing reports this URL as a potential threat.", 65))
    else:
        feeds["google_safe_browsing"] = {"status": "not_configured", "matched": False}
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if vt_key:
        try:
            status, _, response, _ = safe_request(
                "https://www.virustotal.com/api/v3/urls/" + base64.urlsafe_b64encode(url.encode()).decode().rstrip("="),
                headers={"x-apikey": vt_key}, max_bytes=200_000, follow_redirects=False,
            )
            data = json.loads(response)
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            positives = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
            feeds["virustotal"] = {"status": "checked" if status == 200 else "unavailable", "matched": positives > 0, "detections": positives}
        except (OSError, ValueError, TypeError, json.JSONDecodeError, ScanError):
            feeds["virustotal"] = {"status": "unavailable", "matched": False}
        checks.append(_check("virustotal", "VirusTotal detection", feeds["virustotal"]["matched"], "VirusTotal reports security-vendor detections for this URL.", min(70, 35 + 5 * feeds["virustotal"].get("detections", 0))))
    else:
        feeds["virustotal"] = {"status": "not_configured", "matched": False}
    return {"feeds": feeds, "checks": checks}


def scan_url(raw_url: str) -> dict[str, Any]:
    url = normalize_url(raw_url)
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    addresses = resolve_public(host, port)
    domain = _registrable_domain(host)
    checks = _url_checks(url, host, domain)
    details = _domain_details(host, parts.scheme, addresses[0] if addresses else None, port)
    if not addresses:
        checks.append(_check(
            "dns_warning",
            "DNS resolution unavailable or skipped",
            False,
            "The hostname could not be resolved or it points to a private/reserved address. Static analysis still ran, but network content checks were skipped for safety.",
            0,
        ))
    if details["ssl"]["valid"] is False and parts.scheme == "https":
        checks.append(_check("ssl_invalid", "HTTPS certificate could not be verified", True, "The HTTPS certificate is invalid, expired, or the secure connection could not be verified.", 18))
    if details.get("age_days") is not None:
        new_domain = details["age_days"] < 180
        checks.append(_check("new_domain", "Recently registered domain", new_domain, f"The domain is approximately {details['age_days']} days old.", 14))
    if addresses:
        try:
            page, page_checks = _page_details(url, host)
            checks.extend(page_checks)
        except (OSError, ssl.SSLError, TimeoutError, http.client.HTTPException, ScanError) as exc:
            page = {"status_code": None, "redirect_chain": [url], "title": None, "login_form": None,
                    "forms_cross_domain": None, "hidden_iframes": None, "external_links": None,
                    "favicon": None, "error": str(exc)}
            checks.append(_check("page_unavailable", "Page content could not be inspected", False, "The site responded with an error or did not return a supported page.", 0))
    else:
        page = {"status_code": None, "redirect_chain": [url], "title": None, "login_form": None,
                "forms_cross_domain": None, "hidden_iframes": None, "external_links": None,
                "favicon": None, "error": "Network content checks skipped because the host could not be resolved or is private/reserved."}
    feed_results = _feed_results(url, domain)
    checks.extend(feed_results["checks"])
    model_result = classify_url(url)
    model_probability = model_result.get("phishing_probability")
    model_cutoff = model_result.get("threshold", 0.8)
    model_triggered = model_probability is not None and model_probability >= model_cutoff
    xgboost_result = classify_url_xgboost(url)
    xgboost_probability = xgboost_result.get("phishing_probability")
    xgboost_cutoff = xgboost_result.get("threshold", 0.8)
    xgboost_triggered = xgboost_probability is not None and xgboost_probability >= xgboost_cutoff
    model_explanations = []
    if model_probability is not None:
        model_explanations.append(
            f"the byte-level URL model estimates {model_probability:.0%} "
            f"(threshold {model_cutoff:.0%})"
        )
    if xgboost_probability is not None:
        model_explanations.append(
            f"the XGBoost URL-feature model estimates {xgboost_probability:.0%} "
            f"(threshold {xgboost_cutoff:.0%})"
        )
    checks.append(_check(
        "trained_url_models",
        "Trained URL classifier",
        model_triggered or xgboost_triggered,
        (
            f"{'; '.join(model_explanations)}. These are model estimates, not a confirmed threat."
            if model_explanations
            else "No trained URL model returned a prediction; heuristic and feed checks are still used."
        ),
        60 if model_triggered or xgboost_triggered else 0,
    ))
    scoring = score_scan(checks)
    triggered = [item for item in checks if item["triggered"]]
    return {
        "url": url,
        "verdict": scoring["verdict"],
        "risk_score": scoring["risk_score"],
        "max_score": scoring["max_score"],
        "checks": triggered,
        "all_checks": checks,
        "details": {
            "domain": details,
            "page": page,
            "threat_feeds": feed_results["feeds"],
            "model": model_result,
            "xgboost_model": xgboost_result,
        },
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


class ScanRateLimiter:
    def __init__(self, limit: int = 10, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.requests: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, client: str) -> bool:
        with self.lock:
            now = time.monotonic()
            recent = self.requests[client]
            while recent and now - recent[0] >= self.window_seconds:
                recent.popleft()
            if len(recent) >= self.limit:
                return False
            recent.append(now)
            return True
