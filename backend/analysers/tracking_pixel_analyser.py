from html.parser import HTMLParser
from urllib.parse import urlparse


class _ImageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.images = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "img":
            return
        self.images.append({key.lower(): value for key, value in attrs})


def _parse_dimension(value):
    if value is None:
        return None
    clean = str(value).strip().lower().replace("px", "")
    try:
        return int(float(clean))
    except ValueError:
        return None


def _style_hides_image(style):
    style = str(style or "").lower().replace(" ", "")
    return any(
        token in style
        for token in [
            "display:none",
            "visibility:hidden",
            "opacity:0",
            "width:0",
            "height:0",
            "max-height:0",
        ]
    )


def _domain_from_url(url):
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def analyse_tracking_pixels(body_html: str = "") -> dict:
    """
    Detect likely email tracking pixels from hidden or tiny remote images.
    This is heuristic evidence, not proof that tracking occurred.
    """
    parser = _ImageParser()
    parser.feed(body_html or "")

    result = {
        "total_images": len(parser.images),
        "tracking_pixels": [],
        "risk": "NONE",
        "flags": [],
    }

    tracking_terms = (
        "track",
        "open",
        "pixel",
        "beacon",
        "analytics",
        "collect",
        "mailstat",
        "email.",
    )

    for image in parser.images:
        src = image.get("src", "")
        if not src or src.startswith("data:"):
            continue

        width = _parse_dimension(image.get("width"))
        height = _parse_dimension(image.get("height"))
        style = image.get("style", "")
        tiny = width is not None and height is not None and width <= 2 and height <= 2
        hidden = _style_hides_image(style)
        suspicious_src = any(term in src.lower() for term in tracking_terms)

        reasons = []
        if tiny:
            reasons.append(f"tiny remote image ({width}x{height})")
        if hidden:
            reasons.append("hidden by CSS")
        if suspicious_src:
            reasons.append("tracking-like URL pattern")

        if reasons:
            result["tracking_pixels"].append({
                "domain": _domain_from_url(src),
                "src": src[:120] + "..." if len(src) > 120 else src,
                "reasons": reasons,
            })

    count = len(result["tracking_pixels"])
    if count >= 2:
        result["risk"] = "HIGH"
        result["flags"].append(f"{count} likely tracking pixel(s) detected")
    elif count == 1:
        result["risk"] = "MEDIUM"
        result["flags"].append("1 likely tracking pixel detected")

    return result
