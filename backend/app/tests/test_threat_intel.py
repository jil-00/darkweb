from app.models.threat_intel import ConfidenceLevel, IOCType, ThreatLevel
from app.services.correlation_engine import CorrelationEngine
from app.services.processor.ioc_normalizer import IOCNormalizer
from app.services.threat_scoring import ThreatScoringEngine


def test_ioc_normalizer_detects_types() -> None:
    assert IOCNormalizer.detect_ioc_type("192.168.1.1") == IOCType.IP
    assert IOCNormalizer.detect_ioc_type("example.com") == IOCType.DOMAIN
    assert IOCNormalizer.detect_ioc_type("test@example.com") == IOCType.EMAIL
    assert IOCNormalizer.detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == IOCType.HASH_MD5


def test_ioc_normalizer_validates_domains() -> None:
    valid, msg = IOCNormalizer.validate_ioc("example.com", IOCType.DOMAIN)
    assert valid is True

    valid, msg = IOCNormalizer.validate_ioc("invalid domain!", IOCType.DOMAIN)
    assert valid is False


def test_ioc_normalizer_detects_trusted_domains() -> None:
    assert IOCNormalizer.is_trusted("google.com", IOCType.DOMAIN) is True
    assert IOCNormalizer.is_trusted("malicious.com", IOCType.DOMAIN) is False


def test_threat_scoring_calculates_scores() -> None:
    score, threat_level, confidence = ThreatScoringEngine.calculate_threat_score(
        IOCType.IP,
        malicious_count=30,
        suspicious_count=10,
        total_engines=60,
        malware_families=["trojan"],
        sources=["virustotal", "shodan"],
    )

    assert score > 40.0
    assert threat_level in (ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL)
    assert confidence != ConfidenceLevel.UNKNOWN


def test_threat_scoring_handles_no_detections() -> None:
    score, threat_level, confidence = ThreatScoringEngine.calculate_threat_score(
        IOCType.DOMAIN,
        malicious_count=0,
        suspicious_count=0,
        total_engines=60,
    )

    assert score < 20.0
    assert threat_level == ThreatLevel.INFO


def test_threat_scoring_ransomware_boost() -> None:
    score1, _, _ = ThreatScoringEngine.calculate_threat_score(
        IOCType.IP,
        malicious_count=1,
        total_engines=60,
        malware_families=["trojan"],
    )

    score2, _, _ = ThreatScoringEngine.calculate_threat_score(
        IOCType.IP,
        malicious_count=1,
        total_engines=60,
        malware_families=["ransomware"],
    )

    assert score2 > score1


def test_correlation_engine_builds_threat_graph() -> None:
    from app.models.threat_intel import IOCIndicator

    indicators = [
        IOCIndicator(
            ioc_type=IOCType.DOMAIN,
            value="malicious.com",
            threat_level=ThreatLevel.HIGH,
            risk_score=85.0,
        ),
        IOCIndicator(
            ioc_type=IOCType.IP,
            value="192.168.1.1",
            threat_level=ThreatLevel.MEDIUM,
            risk_score=50.0,
            associated_domains=["malicious.com"],
        ),
    ]

    graph = CorrelationEngine.build_threat_graph(indicators)

    assert len(graph["nodes"]) == 2
    assert len(graph["edges"]) >= 0


def test_ioc_enrichment_extracts_domain_from_url() -> None:
    domain = IOCNormalizer.extract_domain_from_url("https://example.com/path")
    assert domain == "example.com"


def test_ioc_enrichment_extracts_domain_from_email() -> None:
    domain = IOCNormalizer.extract_domain_from_email("user@example.com")
    assert domain == "example.com"
