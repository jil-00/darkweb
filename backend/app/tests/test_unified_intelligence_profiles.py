from __future__ import annotations

import asyncio

from app.models.unified_intelligence import ReputationStatus
from app.services.unified_intelligence import UnifiedIntelligenceService


async def _empty_collect(*args, **kwargs):
    return []


def _make_service() -> UnifiedIntelligenceService:
    service = UnifiedIntelligenceService()
    service.vt_connector.collect = _empty_collect  # type: ignore[method-assign]
    service.shodan_connector.collect = _empty_collect  # type: ignore[method-assign]
    service.ipinfo_connector.collect = _empty_collect  # type: ignore[method-assign]
    return service


def test_trusted_targets_stay_low_risk() -> None:
    service = _make_service()

    google_report = asyncio.run(service.enrich("google.com"))
    assert google_report.reputation_status == ReputationStatus.TRUSTED_ENTERPRISE
    assert google_report.threat_score <= 5
    assert google_report.exposure_score >= 70
    assert google_report.confidence_score >= 0.95

    dns_report = asyncio.run(service.enrich("8.8.8.8"))
    assert dns_report.reputation_status == ReputationStatus.TRUSTED_ISP
    assert dns_report.threat_score <= 5
    assert dns_report.exposure_score >= 65

    cloudflare_report = asyncio.run(service.enrich("cloudflare.com"))
    assert cloudflare_report.reputation_status == ReputationStatus.CDN
    assert cloudflare_report.threat_score <= 5
    assert cloudflare_report.exposure_score >= 60


def test_training_and_vulnerable_targets_are_medium_risk() -> None:
    service = _make_service()

    vuln_report = asyncio.run(service.enrich("testphp.vulnweb.com"))
    assert vuln_report.reputation_status == ReputationStatus.SUSPICIOUS_TESTING
    assert 35 <= vuln_report.threat_score <= 55
    assert vuln_report.exposure_score >= 60
    assert vuln_report.confidence_score >= 0.8

    safebrowsing_report = asyncio.run(service.enrich("testsafebrowsing.appspot.com"))
    assert safebrowsing_report.reputation_status == ReputationStatus.SUSPICIOUS_TESTING
    assert 30 <= safebrowsing_report.threat_score <= 55


def test_phishing_and_dark_web_targets_are_high_risk() -> None:
    service = _make_service()

    phishing_report = asyncio.run(service.enrich("paypal-security-alert-login.com"))
    assert phishing_report.reputation_status == ReputationStatus.POTENTIAL_PHISHING
    assert phishing_report.threat_score >= 80
    assert phishing_report.exposure_score <= 40

    microsoft_report = asyncio.run(service.enrich("secure-microsoft-authenticate.net"))
    assert microsoft_report.reputation_status == ReputationStatus.POTENTIAL_PHISHING
    assert microsoft_report.threat_score >= 80

    onion_report = asyncio.run(service.enrich("darkshadow-market.onion"))
    assert onion_report.reputation_status == ReputationStatus.MALICIOUS
    assert onion_report.threat_score >= 90
    assert onion_report.exposure_score <= 40
