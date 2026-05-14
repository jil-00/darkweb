from datetime import datetime, timezone

from loguru import logger

from app.models.threat_intel import (
    ConfidenceLevel,
    EnrichmentRequest,
    EnrichmentResponse,
    IOCIndicator,
    IOCSource,
    IOCType,
    ThreatLevel,
    ThreatIntelligenceReport,
)
from app.services.correlation_engine import CorrelationEngine
from app.services.ingestion.external_sources import (
    IPinfoConnector,
    ShodanConnector,
    VirusTotalConnector,
)
from app.services.processor.ioc_normalizer import IOCNormalizer
from app.services.threat_scoring import ThreatScoringEngine


class IOCEnrichmentEngine:
    """Orchestrate IOC enrichment across multiple threat intelligence sources."""

    def __init__(self):
        self.virustotal = VirusTotalConnector()
        self.shodan = ShodanConnector()
        self.ipinfo = IPinfoConnector()

    async def enrich_ioc(self, request: EnrichmentRequest) -> EnrichmentResponse:
        """
        Comprehensively enrich an IOC with threat intelligence.

        Returns: EnrichmentResponse with all threat intelligence data
        """
        ioc_value = IOCNormalizer.normalize(request.ioc_value)
        ioc_type = request.ioc_type or IOCNormalizer.detect_ioc_type(ioc_value)

        if not ioc_type:
            return EnrichmentResponse(
                status="failed",
                ioc=IOCIndicator(ioc_type=IOCType.DOMAIN, value=ioc_value),
                error_message=f"Unable to determine IOC type for: {ioc_value}",
                sources_queried=[],
                sources_failed=[],
            )

        is_valid, error_msg = IOCNormalizer.validate_ioc(ioc_value, ioc_type)
        if not is_valid:
            return EnrichmentResponse(
                status="failed",
                ioc=IOCIndicator(ioc_type=ioc_type, value=ioc_value),
                error_message=error_msg,
                sources_queried=[],
                sources_failed=[],
            )

        if IOCNormalizer.is_trusted(ioc_value, ioc_type):
            logger.info("IOC is from trusted source, skipping enrichment: {}", ioc_value)
            return EnrichmentResponse(
                status="success",
                ioc=IOCIndicator(
                    ioc_type=ioc_type,
                    value=ioc_value,
                    threat_level=ThreatLevel.LOW,
                    confidence=ConfidenceLevel.CERTAIN,
                    risk_score=5.0,
                ),
                sources_queried=[],
            )

        virustotal_data = None
        shodan_data = None
        ipinfo_data = None
        sources_queried = []
        sources_failed = []

        try:
            virustotal_data = await self._query_virustotal(ioc_value, ioc_type)
            sources_queried.append(IOCSource.VIRUSTOTAL)
        except Exception as exc:
            logger.warning("VirusTotal enrichment failed: {}", exc)
            sources_failed.append(IOCSource.VIRUSTOTAL)

        try:
            shodan_data = await self._query_shodan(ioc_value, ioc_type)
            sources_queried.append(IOCSource.SHODAN)
        except Exception as exc:
            logger.warning("Shodan enrichment failed: {}", exc)
            sources_failed.append(IOCSource.SHODAN)

        try:
            ipinfo_data = await self._query_ipinfo(ioc_value, ioc_type)
            sources_queried.append(IOCSource.IPINFO)
        except Exception as exc:
            logger.warning("IPinfo enrichment failed: {}", exc)
            sources_failed.append(IOCSource.IPINFO)

        ioc = self._build_ioc_indicator(
            ioc_type,
            ioc_value,
            virustotal_data,
            shodan_data,
            ipinfo_data,
            [s.value for s in sources_queried],
        )

        status = "success" if sources_queried else "failed"
        if sources_failed and sources_queried:
            status = "partial"

        report = ThreatIntelligenceReport(
            ioc=ioc,
            virustotal_data=virustotal_data if request.include_raw_data else None,
            shodan_data=shodan_data if request.include_raw_data else None,
            ipinfo_data=ipinfo_data if request.include_raw_data else None,
            recommendations=CorrelationEngine.get_investigation_recommendations([ioc]),
        )

        return EnrichmentResponse(
            status=status,
            ioc=ioc,
            report=report,
            sources_queried=sources_queried,
            sources_failed=sources_failed,
        )

    async def _query_virustotal(self, ioc_value: str, ioc_type: IOCType) -> dict | None:
        """Query VirusTotal for enrichment data."""
        if not self.virustotal.api_key:
            return None

        findings = self.virustotal.collect_sync(ioc_value, ioc_type.value)
        if not findings:
            return None

        data = findings[0].get("payload", {})
        return {
            "detections": data.get("analysis_stats", {}),
            "attributes": data.get("attributes", {}),
        }

    async def _query_shodan(self, ioc_value: str, ioc_type: IOCType) -> dict | None:
        """Query Shodan for enrichment data."""
        if not self.shodan.api_key:
            return None

        if ioc_type not in (IOCType.IP, IOCType.DOMAIN):
            return None

        findings = self.shodan.collect_sync(ioc_value, ioc_type.value)
        if not findings:
            return None

        data = findings[0].get("payload", {})
        return {
            "total_results": data.get("total", 0),
            "open_ports": data.get("open_ports", []),
            "top_match": data.get("top_match", {}),
        }

    async def _query_ipinfo(self, ioc_value: str, ioc_type: IOCType) -> dict | None:
        """Query IPinfo for enrichment data."""
        if not self.ipinfo.api_key:
            return None

        if ioc_type != IOCType.IP:
            return None

        findings = self.ipinfo.collect_sync(ioc_value, ioc_type.value)
        if not findings:
            return None

        data = findings[0].get("payload", {})
        return {
            "privacy": data.get("privacy", {}),
            "abuse": data.get("abuse", {}),
            "ipinfo": data.get("ipinfo", {}),
        }

    def _build_ioc_indicator(
        self,
        ioc_type: IOCType,
        ioc_value: str,
        virustotal_data: dict | None,
        shodan_data: dict | None,
        ipinfo_data: dict | None,
        sources: list[str],
    ) -> IOCIndicator:
        """Build comprehensive IOC indicator from enrichment data."""
        is_malicious = False
        is_suspicious = False
        malware_families = []
        malicious_count = 0
        suspicious_count = 0

        if virustotal_data:
            detections = virustotal_data.get("detections", {})
            malicious_count = int(detections.get("malicious", 0) or 0)
            suspicious_count = int(detections.get("suspicious", 0) or 0)

            if malicious_count > 0:
                is_malicious = True

            if suspicious_count > 0:
                is_suspicious = True

        if shodan_data and shodan_data.get("total_results", 0) > 0:
            is_suspicious = True

        risk_score, threat_level, confidence = ThreatScoringEngine.calculate_threat_score(
            ioc_type,
            malicious_count=malicious_count,
            suspicious_count=suspicious_count,
            total_engines=1,
            malware_families=malware_families,
            sources=sources,
        )

        tags = ThreatScoringEngine.get_threat_tags(ioc_type, threat_level, malware_families)

        associated_ips = []
        associated_domains = []

        if shodan_data and "top_match" in shodan_data:
            top = shodan_data["top_match"]
            if "ip_str" in top:
                associated_ips.append(top["ip_str"])

        return IOCIndicator(
            ioc_type=ioc_type,
            value=ioc_value,
            sources=[IOCSource(s) for s in sources],
            threat_level=threat_level,
            confidence=confidence,
            risk_score=risk_score,
            is_malicious=is_malicious,
            is_suspicious=is_suspicious,
            malware_families=malware_families,
            associated_ips=associated_ips,
            associated_domains=associated_domains,
            last_seen=datetime.now(timezone.utc).isoformat(),
            tags=tags,
            raw_data={
                "virustotal": virustotal_data or {},
                "shodan": shodan_data or {},
                "ipinfo": ipinfo_data or {},
            },
        )
