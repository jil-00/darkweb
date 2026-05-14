"""
Unified intelligence models for multi-source threat correlation and analysis.
Normalizes data from VirusTotal, Shodan, and IPinfo into a single standardized structure.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk severity classification."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class ReputationStatus(str, Enum):
    """Infrastructure reputation assessment."""
    TRUSTED_ENTERPRISE = "Trusted Enterprise Infrastructure"
    TRUSTED_ISP = "Trusted ISP Infrastructure"
    HOSTING_PROVIDER = "Known Hosting Provider"
    CDN = "CDN Infrastructure"
    NEUTRAL = "Neutral Reputation"
    SUSPICIOUS = "Suspicious Reputation"
    MALICIOUS = "Malicious Reputation"
    UNKNOWN = "Unknown Reputation"


class FindingType(str, Enum):
    """Types of findings from correlated intelligence."""
    MALICIOUS_DETECTION = "Malicious Detection"
    SUSPICIOUS_ACTIVITY = "Suspicious Activity"
    VULNERABLE_SERVICE = "Vulnerable Service"
    RISKY_INFRASTRUCTURE = "Risky Infrastructure"
    TRUSTED_ENTITY = "Trusted Entity"
    BENIGN = "Benign"


class Finding(BaseModel):
    """Single correlated finding with explanation."""
    finding_type: FindingType
    title: str
    description: str
    severity: RiskLevel
    source: str  # "VirusTotal", "Shodan", "IPinfo", "Correlation"
    evidence: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)


class ScoreExplanation(BaseModel):
    """Explanation for threat scoring decisions."""
    score: float
    reasoning: str
    key_factors: list[str] = Field(default_factory=list)


class VirusTotalIntelligence(BaseModel):
    """Normalized VirusTotal intelligence with full provider data."""
    reputation: Optional[str] = None
    malicious_vendors: int = 0
    suspicious_vendors: int = 0
    undetected_vendors: int = 0
    harmless_vendors: int = 0
    community_score: Optional[float] = None
    malware_families: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    last_analysis_date: Optional[datetime] = None
    detection_engines: dict[str, str] = Field(default_factory=dict)
    related_domains: list[str] = Field(default_factory=list)
    related_ips: list[str] = Field(default_factory=list)
    passive_dns: list[dict] = Field(default_factory=list)
    sandbox_results: dict[str, Any] = Field(default_factory=dict)
    network_reputation: Optional[str] = None
    popular_ranks: dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: list[str] = Field(default_factory=list)
    threat_classifications: list[str] = Field(default_factory=list)
    raw_response: dict[str, Any] = Field(default_factory=dict)


class ShodanIntelligence(BaseModel):
    """Normalized Shodan intelligence with full provider data."""
    open_ports: list[int] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    products: dict[str, str] = Field(default_factory=dict)
    cves: list[dict] = Field(default_factory=list)  # CVE ID, CVSS score
    cvss_scores: list[float] = Field(default_factory=list)
    ssl_valid: Optional[bool] = None
    ssl_certificate_info: dict[str, Any] = Field(default_factory=dict)
    ssl_cipher_suites: list[str] = Field(default_factory=list)
    server_banner: Optional[str] = None
    hostnames: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    asn: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    operating_system: Optional[str] = None
    http_headers: dict[str, str] = Field(default_factory=dict)
    http_body_preview: Optional[str] = None
    ssh_fingerprint: Optional[str] = None
    cdn_information: Optional[str] = None
    hosting_provider: Optional[str] = None
    internet_exposure_metadata: dict[str, Any] = Field(default_factory=dict)
    last_seen: Optional[datetime] = None
    raw_response: dict[str, Any] = Field(default_factory=dict)


class IpinfoIntelligence(BaseModel):
    """Normalized IPinfo intelligence with full provider data."""
    asn: Optional[str] = None
    organization: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    postal_code: Optional[str] = None
    timezone: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    hosting_type: Optional[str] = None
    is_anycast: Optional[bool] = None
    network_owner: Optional[str] = None
    is_vpn: Optional[bool] = None
    is_proxy: Optional[bool] = None
    is_tor: Optional[bool] = None
    is_datacenter: Optional[bool] = None
    carrier_info: Optional[dict] = None
    privacy_flags: dict[str, bool] = Field(default_factory=dict)
    raw_response: dict[str, Any] = Field(default_factory=dict)


class UnifiedIntelligenceReport(BaseModel):
    """
    Unified correlated intelligence report from multiple sources.
    Single source of truth for all threat analysis.
    """
    # Target information
    ioc_value: str
    ioc_type: str  # ip, domain, hash, url, email
    
    # Scoring - Separated and Explainable
    exposure_score: float = Field(ge=0.0, le=100.0)  # Internet visibility
    threat_score: float = Field(ge=0.0, le=100.0)  # Maliciousness
    reputation_status: ReputationStatus = ReputationStatus.UNKNOWN
    confidence_score: float = Field(ge=0.0, le=1.0)  # Intelligence reliability
    risk_level: RiskLevel  # Derived from threat_score
    
    # Score Explanations
    exposure_reasoning: Optional[ScoreExplanation] = None
    threat_reasoning: Optional[ScoreExplanation] = None
    reputation_reasoning: Optional[str] = None
    confidence_reasoning: Optional[str] = None
    
    # Findings
    findings: list[Finding] = Field(default_factory=list)
    findings_summary: str = ""
    
    # Source intelligence
    virustotal: Optional[VirusTotalIntelligence] = None
    shodan: Optional[ShodanIntelligence] = None
    ipinfo: Optional[IpinfoIntelligence] = None
    
    # Metadata
    sources_queried: list[str] = Field(default_factory=list)
    sources_failed: list[str] = Field(default_factory=list)
    investigation_timestamp: datetime
    last_updated: datetime
    analyst_notes: Optional[str] = None
    
    class Config:
        """Pydantic configuration."""
        json_schema_extra = {
            "example": {
                "ioc_value": "google.com",
                "ioc_type": "domain",
                "threat_score": 5,
                "risk_level": "Low",
                "confidence_score": 0.96,
                "findings": [
                    {
                        "finding_type": "Benign",
                        "title": "No Malicious Detections",
                        "description": "No malware detected by security vendors",
                        "severity": "Info",
                        "source": "VirusTotal",
                        "confidence": 0.99
                    }
                ],
                "sources_queried": ["virustotal", "shodan", "ipinfo"],
                "sources_failed": [],
                "investigation_timestamp": "2026-05-13T04:15:19Z"
            }
        }


class CorrelationMetadata(BaseModel):
    """Metadata about correlation analysis."""
    correlation_timestamp: datetime
    sources_count: int
    findings_count: int
    highest_risk_finding: Optional[RiskLevel] = None
    analyst_can_export: bool = True


class ExportRequest(BaseModel):
    """Request to export investigation report."""
    ioc_value: str
    format: str = Field(pattern="^(pdf|csv)$")
    include_raw_data: bool = False
    analyst_notes: Optional[str] = None
