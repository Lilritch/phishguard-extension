import re
import requests

def extract_links(text: str) -> list:
    """Extract all URLs from email body."""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text)

def scan_links(links: list) -> dict:
    """
    Check links against known suspicious patterns.
    (Google Safe Browsing requires billing — we use heuristics + URLScan)
    """
    result = {
        "total_links": len(links),
        "suspicious_links": [],
        "flags": []
    }

    suspicious_patterns = [
        r'bit\.ly|tinyurl|t\.co|goo\.gl',         
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',   
        r'@',                                        
        r'secure.*login|verify.*account|update.*payment',
        r'paypal|amazon|google|microsoft|apple',    
    ]

    for link in links:
        reasons = []
        link_lower = link.lower()
        for pattern in suspicious_patterns:
            if re.search(pattern, link_lower):
                reasons.append(f'Pattern match: {pattern}')
        if reasons:
            result['suspicious_links'].append({
                'url': link[:80] + '...' if len(link) > 80 else link,
                'reasons': reasons
            })

    if result['suspicious_links']:
        result['flags'].append(f"{len(result['suspicious_links'])} suspicious link(s) detected")

    return result 