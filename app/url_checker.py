
import re
from urllib.parse import urlparse


def check_url(url):
    url = url.strip()

    if not url:
        return {
            "risk": "Invalid URL",
            "score": 0,
            "reasons": ["Please enter a URL."]
        }

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return {
            "risk": "Invalid URL",
            "score": 0,
            "reasons": ["The URL format is invalid."]
        }

    score = 0
    reasons = []

    # 1. Missing HTTPS
    if parsed.scheme.lower() != "https":
        score += 15
        reasons.append("The website does not use HTTPS.")

    # 2. IP address instead of domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        score += 30
        reasons.append("The URL uses an IP address.")

    # 3. Suspicious keywords
    suspicious_words = [
        "login", "verify", "update", "secure",
        "account", "banking", "free", "prize",
        "reward", "claim", "urgent", "password",
        "wallet", "confirm", "suspended"
    ]

    found_words = [word for word in suspicious_words if word in url.lower()]

    if found_words:
        score += min(len(found_words) * 10, 30)
        reasons.append(
            "Suspicious keywords detected: " + ", ".join(found_words)
        )

    # 4. URL shorteners
    shorteners = [
        "bit.ly", "tinyurl.com", "t.co",
        "is.gd", "cutt.ly"
    ]

    if any(
        hostname.lower() == domain or hostname.lower().endswith("." + domain)
        for domain in shorteners
    ):
        score += 25
        reasons.append("The URL uses a URL-shortening service.")

    # 5. Excessive subdomains
    if len(hostname.split(".")) > 3:
        score += 15
        reasons.append("The URL contains many subdomains.")

    # 6. @ symbol
    if "@" in url:
        score += 20
        reasons.append("The URL contains an unusual @ symbol.")

    score = min(score, 100)

    if score >= 60:
        risk = "High Risk"
    elif score >= 30:
        risk = "Medium Risk"
    else:
        risk = "Low Risk"

    if not reasons:
        reasons.append("No suspicious URL patterns were detected.")

    return {
        "risk": risk,
        "score": score,
        "reasons": reasons
    }
