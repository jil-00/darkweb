from urllib.parse import urlparse

from app.core.config import get_settings


SAFE_DOMAINS = {
    "google.com",
    "github.com",
    "microsoft.com",
}


def _source_weight(source: str) -> float:
    settings = get_settings()
    source_map = {
        "breach_db": settings.risk_weight_breach_db,
        "forum": settings.risk_weight_forum,
        "paste_feed": settings.risk_weight_paste,
        "breach": 1.0,
        "paste": settings.risk_weight_paste,
        "virustotal": settings.risk_weight_breach_db,
        "shodan": settings.risk_weight_forum,
        "ipinfo": settings.risk_weight_paste,
        "otx": settings.risk_weight_paste,
    }
    return source_map.get(source, 0.5)


def _sensitivity_weight(label: str) -> float:
    settings = get_settings()
    sensitivity_map = {
        "password": settings.risk_sensitivity_password,
        "email": settings.risk_sensitivity_email,
        "username": settings.risk_sensitivity_username,
        "domain": settings.risk_sensitivity_domain,
    }
    return sensitivity_map.get(label, settings.risk_sensitivity_email)


def _normalize_domain(value: str | None) -> str:
    if not value:
        return ""

    text = value.strip().lower()
    if "://" not in text:
        text = f"//{text}"

    parsed = urlparse(text)
    host = parsed.netloc or parsed.path
    host = host.split("/")[0].split(":")[0].strip()
    if host.startswith("www."):
        host = host[4:]
    return host


def _is_safe_domain(domain: str | None) -> bool:
    normalized = _normalize_domain(domain)
    if not normalized:
        return False

    return any(normalized == safe or normalized.endswith(f".{safe}") for safe in SAFE_DOMAINS)


def score_finding(item: dict) -> float:
    source_weight = float(item.get("source_weight", _source_weight(item.get("source", ""))))
    frequency = min(int(item.get("occurrences", 1)), 5)
    sensitivity = float(
        item.get("sensitivity", _sensitivity_weight(item.get("sensitivity_label", "email")))
    )
    risk = source_weight * sensitivity * frequency * 10.0
    return round(min(100.0, risk), 2)


def calculate_risk(findings: list[dict], domain: str | None = None) -> float:
    if not findings:
        return 0.0

    if _is_safe_domain(domain):
        return 5.0

    total_weight = 0.0
    total_score = 0.0
    for item in findings:
        source_weight = float(item.get("source_weight", _source_weight(item.get("source", ""))))
        sensitivity = float(
            item.get("sensitivity", _sensitivity_weight(item.get("sensitivity_label", "email")))
        )
        occurrences = min(int(item.get("occurrences", 1)), 5)
        weight = source_weight * sensitivity
        score = occurrences / 5.0
        total_weight += weight
        total_score += weight * score

    if total_weight <= 0:
        return 0.0

    final = (total_score / total_weight) * 100.0

    normalized_domain = _normalize_domain(domain)
    if normalized_domain.endswith(".gov") or normalized_domain.endswith(".edu"):
        final *= 0.3

    if len(findings) <= 2:
        final *= 0.4

    return round(min(final, 100.0), 2)


def score_result(
    findings: list[dict],
    domain: str | None = None,
    query_type: str | None = None,
) -> float:
    return calculate_risk(findings, domain)