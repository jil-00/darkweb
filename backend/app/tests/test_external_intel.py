from __future__ import annotations

from types import SimpleNamespace

from app.core.config import Settings
from app.services.ingestion.external_sources import (
    IPinfoConnector,
    ShodanConnector,
    VirusTotalConnector,
    validate_external_api_configuration,
)


class FakeResponse:
    def __init__(self, status_code: int = 200, payload=None, headers=None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {"content-type": "application/json"}

    def json(self):
        return self._payload


def test_external_api_status_flags_missing_keys() -> None:
    settings = Settings(
        VIRUSTOTAL_API_KEY="vt-secret",
        SHODAN_API_KEY="",
        IPINFO_TOKEN=None,
    )

    assert settings.external_api_status() == {
        "virustotal": True,
        "shodan": False,
        "ipinfo": False,
    }
    assert settings.missing_external_env_vars() == ["SHODAN_API_KEY", "IPINFO_TOKEN"]


def test_validate_external_api_configuration_returns_status() -> None:
    settings = Settings(
        VIRUSTOTAL_API_KEY="vt-secret",
        SHODAN_API_KEY="shodan-secret",
        IPINFO_TOKEN="ipinfo-secret",
    )

    assert validate_external_api_configuration(settings) == {
        "virustotal": True,
        "shodan": True,
        "ipinfo": True,
    }


def test_virustotal_collector_uses_analysis_stats() -> None:
    collector = VirusTotalConnector(
        settings=Settings(VIRUSTOTAL_API_KEY="vt-secret")
    )
    collector.session.request = lambda **kwargs: FakeResponse(
        payload={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 1,
                        "harmless": 10,
                    },
                    "first_submission_date": 1700000000,
                    "last_modification_date": 1700000500,
                }
            }
        }
    )

    findings = collector.collect_sync("example.com", "domain")

    assert len(findings) == 1
    assert findings[0]["source"] == "virustotal"
    assert findings[0]["payload"]["occurrences"] == 3


def test_shodan_collector_uses_matches_payload() -> None:
    collector = ShodanConnector(settings=Settings(SHODAN_API_KEY="shodan-secret"))
    collector.session.request = lambda **kwargs: FakeResponse(
        payload={
            "total": 2,
            "matches": [
                {"port": 443, "ip_str": "1.2.3.4"},
                {"port": 80, "ip_str": "1.2.3.4"},
            ],
        }
    )

    findings = collector.collect_sync("example.com", "domain")

    assert len(findings) == 1
    assert findings[0]["source"] == "shodan"
    assert findings[0]["payload"]["occurrences"] == 2
    assert findings[0]["payload"]["provider_payload"]["total"] == 2


def test_ipinfo_collector_handles_privacy_flags() -> None:
    collector = IPinfoConnector(settings=Settings(IPINFO_TOKEN="ipinfo-secret"))
    collector.session.request = lambda **kwargs: FakeResponse(
        payload={
            "ip": "1.2.3.4",
            "privacy": {"vpn": True, "proxy": False, "tor": False, "relay": False, "hosting": True},
            "abuse": {"is_abuse": False},
        }
    )

    findings = collector.collect_sync("1.2.3.4", "domain")

    assert len(findings) == 1
    assert findings[0]["source"] == "ipinfo"
    assert findings[0]["payload"]["occurrences"] == 2
