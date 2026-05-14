from datetime import datetime, timedelta, timezone

from loguru import logger

from app.models.threat_intel import ConfidenceLevel, IOCType, ThreatLevel
from app.services.processor.ioc_normalizer import IOCNormalizer


class ThreatScoringEngine:
    """Calculate threat scores for IOCs based on multiple factors."""

    # Base scores by threat level
    THREAT_LEVEL_SCORES = {
        ThreatLevel.CRITICAL: 95.0,
        ThreatLevel.HIGH: 75.0,
        ThreatLevel.MEDIUM: 50.0,
        ThreatLevel.LOW: 25.0,
        ThreatLevel.INFO: 5.0,
    }

    # Confidence multipliers
    CONFIDENCE_MULTIPLIERS = {
        ConfidenceLevel.CERTAIN: 1.0,
        ConfidenceLevel.HIGH: 0.9,
        ConfidenceLevel.MEDIUM: 0.7,
        ConfidenceLevel.LOW: 0.5,
        ConfidenceLevel.UNKNOWN: 0.3,
    }

    # Source reliability weights
    SOURCE_WEIGHTS = {
        "virustotal": 0.95,
        "shodan": 0.80,
        "ipinfo": 0.70,
        "internal_db": 0.85,
        "paste_site": 0.60,
    }

    # Malware family severity boost
    MALWARE_FAMILY_SEVERITY = {
        "ransomware": 0.95,
        "trojan": 0.90,
        "botnet": 0.85,
        "worm": 0.80,
        "rootkit": 0.90,
        "spyware": 0.75,
        "adware": 0.40,
        "potentially_unwanted": 0.30,
    }

    @classmethod
    def calculate_threat_score(
        cls,
        ioc_type: IOCType,
        malicious_count: int = 0,
        suspicious_count: int = 0,
        total_engines: int = 1,
        malware_families: list[str] | None = None,
        sources: list[str] | None = None,
        last_seen_days_ago: int | None = None,
    ) -> tuple[float, ThreatLevel, ConfidenceLevel]:
        """
        Calculate comprehensive threat score for an IOC.

        Returns: (score, threat_level, confidence)
        """
        if sources is None:
            sources = []
        if malware_families is None:
            malware_families = []

        score = 0.0

        if total_engines <= 0:
            total_engines = 1

        malicious_ratio = malicious_count / total_engines if total_engines > 0 else 0
        suspicious_ratio = suspicious_count / total_engines if total_engines > 0 else 0

        base_score = (malicious_ratio * 100.0) + (suspicious_ratio * 50.0)
        score = min(100.0, base_score)

        if malware_families:
            malware_boost = cls._calculate_malware_boost(malware_families)
            score = min(100.0, score + malware_boost)

        source_weight = cls._calculate_source_weight(sources) if sources else 0.5
        score *= source_weight

        if last_seen_days_ago is not None and last_seen_days_ago > 90:
            score *= 0.5

        score = round(min(100.0, max(0.0, score)), 2)

        threat_level = cls._score_to_threat_level(score)
        confidence = cls._calculate_confidence(
            malicious_count, suspicious_count, len(sources)
        )

        logger.debug(
            "threat score calculated: ioc_type={}, score={}, threat_level={}, confidence={}",
            ioc_type,
            score,
            threat_level,
            confidence,
        )

        return score, threat_level, confidence

    @classmethod
    def _calculate_malware_boost(cls, malware_families: list[str]) -> float:
        """Calculate severity boost based on malware families."""
        if not malware_families:
            return 0.0

        max_severity = 0.0
        for family in malware_families:
            family_lower = family.lower()
            for key, severity in cls.MALWARE_FAMILY_SEVERITY.items():
                if key in family_lower:
                    max_severity = max(max_severity, severity)
                    break

        return min(30.0, max_severity * 20.0)

    @classmethod
    def _calculate_source_weight(cls, sources: list[str]) -> float:
        """Calculate aggregate weight from multiple sources."""
        if not sources:
            return 0.5

        weights = [cls.SOURCE_WEIGHTS.get(source, 0.5) for source in sources]
        avg_weight = sum(weights) / len(weights)

        source_diversity_bonus = min(0.1, len(set(sources)) * 0.02)

        return min(1.0, avg_weight + source_diversity_bonus)

    @classmethod
    def _score_to_threat_level(cls, score: float) -> ThreatLevel:
        """Map score to threat level."""
        if score >= 90.0:
            return ThreatLevel.CRITICAL
        elif score >= 70.0:
            return ThreatLevel.HIGH
        elif score >= 40.0:
            return ThreatLevel.MEDIUM
        elif score >= 20.0:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.INFO

    @classmethod
    def _calculate_confidence(
        cls, malicious_count: int, suspicious_count: int, source_count: int
    ) -> ConfidenceLevel:
        """Calculate confidence level based on corroboration."""
        if malicious_count >= 5:
            return ConfidenceLevel.CERTAIN
        elif malicious_count >= 3:
            return ConfidenceLevel.HIGH
        elif malicious_count >= 1 and source_count >= 2:
            return ConfidenceLevel.MEDIUM
        elif suspicious_count >= 3 or (malicious_count >= 1 and source_count >= 1):
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.UNKNOWN

    @classmethod
    def should_alert(cls, threat_score: float, threat_level: ThreatLevel) -> bool:
        """Determine if threat warrants an alert."""
        return threat_score >= 60.0 or threat_level in (
            ThreatLevel.CRITICAL,
            ThreatLevel.HIGH,
        )

    @classmethod
    def get_threat_tags(
        cls, ioc_type: IOCType, threat_level: ThreatLevel, malware_families: list[str] | None = None
    ) -> list[str]:
        """Generate threat tags for IOC."""
        tags = [threat_level.value, ioc_type.value]

        if malware_families:
            tags.extend(malware_families[:5])

        return tags
