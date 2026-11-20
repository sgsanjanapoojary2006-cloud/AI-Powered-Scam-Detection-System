
import re


def check_email(email_text):
    email_text = email_text.strip()

    if not email_text:
        return {
            "risk": "Invalid Input",
            "score": 0,
            "reasons": ["Please enter an email to check."]
        }

    if len(email_text) > 10000:
        return {
            "risk": "Invalid Input",
            "score": 0,
            "reasons": ["Email is too long. Maximum 10000 characters."]
        }

    score = 0
    reasons = []
    text = email_text.lower()

    # 1. Urgent and threatening language
    urgent_words = [
        "urgent", "immediately", "within 24 hours",
        "account blocked", "account suspended",
        "permanently blocked", "act now"
    ]

    found_urgent = [word for word in urgent_words if word in text]

    if found_urgent:
        score += min(len(found_urgent) * 10, 25)
        reasons.append(
            "Urgent or threatening language detected: "
            + ", ".join(found_urgent)
        )

    # 2. Requests for sensitive information
    sensitive_words = [
        "password", "otp", "pin", "cvv",
        "debit card", "credit card",
        "bank details", "login credentials"
    ]

    found_sensitive = [
        word for word in sensitive_words if word in text
    ]

    if found_sensitive:
        score += min(len(found_sensitive) * 15, 35)
        reasons.append(
            "Requests for sensitive information detected: "
            + ", ".join(found_sensitive)
        )

    # 3. Prize and lottery scams
    prize_words = [
        "you won", "lottery winner", "claim your prize",
        "free gift", "congratulations"
    ]

    found_prizes = [word for word in prize_words if word in text]

    if found_prizes:
        score += min(len(found_prizes) * 10, 20)
        reasons.append(
            "Possible fake prize or lottery language detected: "
            + ", ".join(found_prizes)
        )

    # 4. Payment requests
    payment_words = [
        "processing fee", "registration fee",
        "pay immediately", "transfer money",
        "advance payment", "send money"
    ]

    found_payments = [
        word for word in payment_words if word in text
    ]

    if found_payments:
        score += min(len(found_payments) * 10, 20)
        reasons.append(
            "Suspicious payment request detected: "
            + ", ".join(found_payments)
        )

    # 5. Suspicious URL patterns
    urls = re.findall(r"https?://[^\s<>\"']+", text)

    suspicious_domains = [
        "bit.ly", "tinyurl.com", "cutt.ly",
        "is.gd", "t.co"
    ]

    for url in urls:
        if any(domain in url for domain in suspicious_domains):
            score += 15
            reasons.append("A URL shortener was found in the email.")
            break

    # 6. Common email manipulation phrases
    manipulation_words = [
        "verify your account",
        "click here to verify",
        "avoid account closure",
        "your account will be closed"
    ]

    found_manipulation = [
        word for word in manipulation_words if word in text
    ]

    if found_manipulation:
        score += min(len(found_manipulation) * 10, 20)
        reasons.append(
            "Suspicious account verification language detected: "
            + ", ".join(found_manipulation)
        )

    score = min(score, 100)

    if score >= 60:
        risk = "High Risk"
    elif score >= 30:
        risk = "Medium Risk"
    else:
        risk = "Low Risk"

    if not reasons:
        reasons.append("No suspicious patterns were detected.")

    return {
        "risk": risk,
        "score": score,
        "reasons": reasons
    }
