from app.services.processor.entity_extractor import extract_entities


SOURCE_WEIGHTS = {
    "breach_db": 0.9,
    "forum": 0.6,
    "paste_feed": 0.7,
    "virustotal": 1.0,
    "shodan": 0.8,
    "ipinfo": 0.4,
}

SENSITIVITY_WEIGHTS = {
    "password": 1.0,
    "email": 0.7,
    "username": 0.5,
    "domain": 0.6,
}


def normalize_finding(raw: dict, query: str, query_type: str) -> dict:
    payload = raw.get("payload", {})
    snippet = f"{payload.get('match', query)}"
    entities = extract_entities(snippet)
    contains_password = bool(payload.get("contains_password", False))
    sensitivity_label = "password" if contains_password else query_type

    category = "credential" if contains_password else "pii"
    if query_type == "domain":
        category = "internal"

    return {
        "source": raw.get("source", "unknown"),
        "source_type": raw.get("source_type", "osint"),
        "observed_value": payload.get("match", query),
        "matched_entity": query,
        "category": category,
        "data_type": query_type,
        "sensitivity_label": sensitivity_label,
        "sensitivity": SENSITIVITY_WEIGHTS.get(sensitivity_label, 0.7),
        "source_weight": SOURCE_WEIGHTS.get(raw.get("source", ""), 0.5),
        "occurrences": int(payload.get("occurrences", 1)),
        "first_seen": raw.get("first_seen"),
        "last_seen": raw.get("last_seen"),
        "raw": {
            "payload": payload,
            "entities": {
                "emails": sorted(entities["emails"]),
                "domains": sorted(entities["domains"]),
                "usernames": sorted(entities["usernames"]),
            },
        },
    }
