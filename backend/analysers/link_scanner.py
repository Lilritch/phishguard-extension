import re
from urllib.parse import urlparse
from urllib.parse import parse_qs


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
}

HIGH_VALUE_BRANDS = {
    "paypal",
    "amazon",
    "google",
    "microsoft",
    "apple",
    "github",
    "supabase",
    "vercel",
    "unitec",
}


def extract_links(text: str) -> list:
    """Extract all URLs from email body or appended link hrefs."""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return [link.rstrip(').,;') for link in re.findall(url_pattern, text or "")]


def get_domain(value: str) -> str:
    try:
        parsed = urlparse(value if value.startswith("http") else f"https://{value}")
        return (parsed.hostname or "").lower().replace("www.", "", 1)
    except Exception:
        return ""


def unwrap_redirect_url(link: str) -> str:
    try:
        parsed = urlparse(link)
        host = (parsed.hostname or "").lower().replace("www.", "", 1)
        if host in {"google.com", "mail.google.com"}:
            query = parse_qs(parsed.query)
            redirected = (query.get("q") or query.get("url") or [None])[0]
            if redirected and redirected.startswith(("http://", "https://")):
                return redirected
    except Exception:
        return link
    return link


def is_ip_domain(domain: str) -> bool:
    return bool(re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', domain or ""))


def is_same_or_subdomain(link_domain: str, sender_domain: str) -> bool:
    if not link_domain or not sender_domain:
        return False
    sender_domain = sender_domain.lower().replace("www.", "", 1)
    return link_domain == sender_domain or link_domain.endswith(f".{sender_domain}")


def scan_links(links: list, sender_domain: str = "") -> dict:
    """
    Sender-aware URL heuristic scanner.

    A trusted-looking sender name is not enough. Links are safer only when they
    resolve to the sender's domain/subdomain and avoid structural phishing
    indicators such as shorteners, IP literals, userinfo, or mismatched brands.
    """
    result = {
        "total_links": len(links),
        "link_domains": [],
        "same_domain_links": 0,
        "external_links": 0,
        "suspicious_links": [],
        "flags": []
    }

    sender_domain = get_domain(sender_domain) if sender_domain else ""
    seen_domains = set()

    for link in links:
        link = unwrap_redirect_url(link)
        reasons = []
        parsed = urlparse(link)
        link_domain = get_domain(link)
        if link_domain:
            seen_domains.add(link_domain)

        same_sender_domain = is_same_or_subdomain(link_domain, sender_domain)
        if same_sender_domain:
            result["same_domain_links"] += 1
        else:
            result["external_links"] += 1

        if link_domain in SHORTENER_DOMAINS:
            reasons.append("URL shortener")
        if is_ip_domain(link_domain):
            reasons.append("IP-address URL")
        if parsed.username or "@" in parsed.netloc:
            reasons.append("URL contains @ userinfo trick")
        if link_domain.count(".") >= 4 and not same_sender_domain:
            reasons.append("Excessive subdomains on external link")

        link_lower = link.lower()
        if re.search(r'secure.*login|verify.*account|update.*payment|reset.*password', link_lower):
            reasons.append("Sensitive action wording in URL")

        mentioned_brands = [brand for brand in HIGH_VALUE_BRANDS if brand in link_lower]
        if mentioned_brands and sender_domain and not same_sender_domain:
            reasons.append(f"Brand-like URL outside sender domain: {', '.join(mentioned_brands[:2])}")

        if sender_domain and not same_sender_domain and re.search(r'\b(login|signin|account|billing|payment|verify)\b', link_lower):
            reasons.append("External sensitive-action link")

        if reasons:
            result['suspicious_links'].append({
                'url': link[:120] + '...' if len(link) > 120 else link,
                'domain': link_domain,
                'reasons': reasons
            })

    result["link_domains"] = sorted(seen_domains)

    if result['suspicious_links']:
        result['flags'].append(f"{len(result['suspicious_links'])} suspicious link(s) detected")
    if sender_domain and result["total_links"] and result["same_domain_links"] == result["total_links"]:
        result["flags"].append("All visible links stay on the sender domain")

    return result
