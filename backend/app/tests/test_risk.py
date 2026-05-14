from app.services.risk import calculate_risk, score_finding, score_result


def test_score_finding_bounds_to_100() -> None:
    item = {"source_weight": 2.0, "occurrences": 20, "sensitivity": 2.0}
    assert score_finding(item) == 100.0


def test_score_result_average() -> None:
    findings = [
        {"source_weight": 1.0, "occurrences": 2, "sensitivity": 1.0},
        {"source_weight": 1.2, "occurrences": 3, "sensitivity": 1.1},
    ]
    assert score_result(findings) > 0


def test_calculate_risk_trusted_domain_stays_low() -> None:
    findings = [
        {"source_weight": 2.0, "occurrences": 20, "sensitivity": 2.0},
    ]
    assert calculate_risk(findings, domain="google.com") == 5.0


def test_score_result_subdomain_of_trusted_domain_stays_low() -> None:
    findings = [
        {"source_weight": 1.8, "occurrences": 10, "sensitivity": 1.5},
    ]
    assert score_result(findings, domain="mail.google.com", query_type="domain") == 5.0


def test_calculate_risk_domain_false_positive_controls() -> None:
    findings = [
        {"source_weight": 0.9, "occurrences": 1, "sensitivity": 0.7},
        {"source_weight": 0.6, "occurrences": 2, "sensitivity": 0.7},
    ]
    assert calculate_risk(findings, domain="randomsite.xyz") < 15


def test_calculate_risk_gov_edu_discount() -> None:
    findings = [
        {"source_weight": 1.0, "occurrences": 3, "sensitivity": 1.0},
        {"source_weight": 1.0, "occurrences": 3, "sensitivity": 1.0},
    ]
    assert calculate_risk(findings, domain="agency.gov") < calculate_risk(findings, domain="example.com")


def test_weighted_average_scoring_stays_balanced() -> None:
    findings = [
        {"source": "virustotal", "occurrences": 1, "sensitivity": 0.7},
        {"source": "shodan", "occurrences": 2, "sensitivity": 0.6},
    ]
    score = calculate_risk(findings, domain="example.com")
    assert 5.0 < score < 50.0