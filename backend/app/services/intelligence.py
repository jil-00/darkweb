import re
from collections import defaultdict

from app.services.ingestion import collect_from_sources
from app.services.processor import deduplicate_entries, normalize_finding
from app.services.risk import score_result


def normalize_query(value: str) -> str:
    return value.strip().lower()


def fuzzy_matches(entity: str, query: str) -> bool:
    if query in entity:
        return True
    for token in query.split("."):
        if token and token in entity:
            return True
    return False


def regex_matches(entity: str, query: str) -> bool:
    try:
        return re.search(query, entity) is not None
    except re.error:
        return False


def correlate_findings(findings: list[dict]) -> dict[str, int]:
    correlation = defaultdict(int)
    for item in findings:
        correlation[item["matched_entity"]] += item.get("occurrences", 1)
    return dict(correlation)


async def run_intelligence(
    query: str,
    query_type: str,
    use_regex: bool,
    fuzzy: bool,
) -> dict:
    normalized_query = normalize_query(query)
    ingestion_rows = await collect_from_sources(normalized_query, query_type)
    raw_findings = [
        normalize_finding(row, normalized_query, query_type) for row in ingestion_rows
    ]

    filtered: list[dict] = []
    for item in raw_findings:
        entity = item.get("matched_entity", "")
        keep = entity == normalized_query
        if fuzzy:
            keep = keep or fuzzy_matches(entity, normalized_query)
        if use_regex:
            keep = keep or regex_matches(entity, normalized_query)
        if keep:
            filtered.append(item)

    deduped = deduplicate_entries(filtered)
    correlation = correlate_findings(deduped)
    risk_score = score_result(deduped, domain=normalized_query, query_type=query_type)

    return {
        "query": normalized_query,
        "query_type": query_type,
        "findings": deduped,
        "correlation": correlation,
        "risk_score": risk_score,
    }