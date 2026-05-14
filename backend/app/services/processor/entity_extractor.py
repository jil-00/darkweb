import re


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
USERNAME_RE = re.compile(r"\b[a-zA-Z0-9_.-]{3,32}\b")


def extract_entities(text: str) -> dict[str, set[str]]:
    return {
        "emails": set(EMAIL_RE.findall(text)),
        "domains": set(DOMAIN_RE.findall(text)),
        "usernames": set(USERNAME_RE.findall(text)),
    }
