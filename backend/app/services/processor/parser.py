def deduplicate_entries(entries: list[dict]) -> list[dict]:
    seen: dict[tuple[str, str], dict] = {}
    for row in entries:
        key = (row.get("source", "unknown"), row.get("matched_entity", ""))
        if key not in seen:
            seen[key] = row
            continue
        seen[key]["occurrences"] = seen[key].get("occurrences", 1) + row.get("occurrences", 1)
    return list(seen.values())
