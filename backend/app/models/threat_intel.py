from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class IOCType(str, Enum):
    """Indicator of Compromise types."""
    IP = "ip"
    DOMAIN = "domain"
    EMAIL = "email"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    USERNAME = "username"
    FILE_PATH = "file_path"


class ThreatLevel(str, Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IOCSource(str, Enum):
    """Threat intelligence sources."""
    VIRUSTOTAL = "virustotal"
    SHODAN = "shodan"
    IPINFO = "ipinfo"
    INTERNAL_DB = "internal_db"
    PASTE_SITE = "paste_site"


class ConfidenceLevel(str, Enum):
    """Confidence in threat assessment."""
    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class IOCIndicator(BaseModel):
    """Normalized IOC indicator with metadata."""
    ioc_type: IOCType
    value: str = Field(min_length=1, max_length=512)
    sources: list[IOCSource] = Field(default_factory=list)
    threat_level: ThreatLevel = ThreatLevel.INFO
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    risk_score: float = Field(ge=0.0, le=100.0)
    is_malicious: bool = False
    is_suspicious: bool = False
    malware_families: list[str] = Field(default_factory=list)
    associated_ips: list[str] = Field(default_factory=list)
    associated_domains: list[str] = Field(default_factory=list)
    last_seen: str | None = None
    first_seen: str | None = None
    tags: list[str] = Field(default_factory=list)
    raw_data: dict = Field(default_factory=dict)


class ThreatIntelligenceReport(BaseModel):
    """Comprehensive threat intelligence report for an IOC."""
    ioc: IOCIndicator
    virustotal_data: dict | None = None
    shodan_data: dict | None = None
    ipinfo_data: dict | None = None
    correlation_matches: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    investigation_notes: str | None = None


class EnrichmentRequest(BaseModel):
    """Request to enrich an IOC with threat intelligence."""
    ioc_value: str = Field(min_length=1, max_length=512)
    ioc_type: IOCType | None = None
    force_refresh: bool = False
    include_raw_data: bool = False


class EnrichmentResponse(BaseModel):
    """Response from IOC enrichment."""
    status: Literal["success", "partial", "failed"]
    ioc: IOCIndicator
    report: ThreatIntelligenceReport | None = None
    error_message: str | None = None
    sources_queried: list[IOCSource] = Field(default_factory=list)
    sources_failed: list[IOCSource] = Field(default_factory=list)
