"""
Unified intelligence correlation service.
Orchestrates collection from multiple sources and normalizes into unified report.
"""

from datetime import datetime, timezone
from typing import Optional
import asyncio

from loguru import logger

from app.models.unified_intelligence import (
    UnifiedIntelligenceReport, VirusTotalIntelligence, ShodanIntelligence,
    IpinfoIntelligence, Finding, FindingType, RiskLevel, RiskLevel as RiskLevelEnum,
    ScoreExplanation, ReputationStatus
)
from app.services.ingestion.external_sources import (
    VirusTotalConnector, ShodanConnector, IPinfoConnector
)
from app.services.processor.ioc_normalizer import IOCNormalizer
from app.services.threat_scoring import ThreatScoringEngine


class UnifiedIntelligenceService:
    """
    Unified threat intelligence service.
    Correlates data from VirusTotal, Shodan, and IPinfo into a single report.
    """

    def __init__(self):
        """Initialize unified intelligence service."""
        self.vt_connector = VirusTotalConnector()
        self.shodan_connector = ShodanConnector()
        self.ipinfo_connector = IPinfoConnector()
        self.normalizer = IOCNormalizer()
        self.scoring_engine = ThreatScoringEngine()

    async def enrich(self, ioc_value: str) -> UnifiedIntelligenceReport:
        """
        Perform unified enrichment on an IOC.

        Args:
            ioc_value: IOC to enrich (IP, domain, hash, URL, email)

        Returns:
            UnifiedIntelligenceReport with correlated intelligence
        """
        try:
            # Detect and normalize IOC
            ioc_type = self.normalizer.detect_ioc_type(ioc_value)
            normalized_ioc = self.normalizer.normalize(ioc_value)
            if not ioc_type:
                raise ValueError(f"Unable to determine IOC type for value: {ioc_value}")

            logger.info(
                "Starting unified enrichment",
                ioc=ioc_value,
                ioc_type=ioc_type.value
            )

            # Collect from all sources in parallel
            vt_result, shodan_result, ipinfo_result = await asyncio.gather(
                self._collect_virustotal(normalized_ioc, ioc_type.value),
                self._collect_shodan(normalized_ioc, ioc_type.value),
                self._collect_ipinfo(normalized_ioc, ioc_type.value),
                return_exceptions=True
            )

            # Track which sources succeeded
            sources_queried = []
            sources_failed = []

            # Process VirusTotal result
            vt_intel = None
            if isinstance(vt_result, Exception):
                logger.warning("VirusTotal collection failed: {}", vt_result)
                sources_failed.append("virustotal")
            elif vt_result:
                vt_intel = vt_result
                sources_queried.append("virustotal")

            # Process Shodan result
            shodan_intel = None
            if isinstance(shodan_result, Exception):
                logger.warning("Shodan collection failed: {}", shodan_result)
                sources_failed.append("shodan")
            elif shodan_result:
                shodan_intel = shodan_result
                sources_queried.append("shodan")

            # Process IPinfo result
            ipinfo_intel = None
            if isinstance(ipinfo_result, Exception):
                logger.warning("IPinfo collection failed: {}", ipinfo_result)
                sources_failed.append("ipinfo")
            elif ipinfo_result:
                ipinfo_intel = ipinfo_result
                sources_queried.append("ipinfo")

            # Generate correlated findings
            findings = self._correlate_findings(
                vt_intel,
                shodan_intel,
                ipinfo_intel,
                normalized_ioc
            )

            # Calculate all four scores separately
            exposure_score = self._calculate_exposure_score(
                shodan_intel,
                ipinfo_intel,
                vt_intel
            )
            threat_score, threat_level = self._calculate_threat_score(
                vt_intel,
                shodan_intel,
                findings
            )
            reputation_status = self._determine_reputation_status(
                ipinfo_intel,
                vt_intel,
                shodan_intel
            )
            confidence_score = self._calculate_confidence_score(
                findings,
                sources_queried
            )

            # Generate explanations for each score
            exposure_reasoning = self._explain_exposure_score(exposure_score, shodan_intel, ipinfo_intel)
            threat_reasoning = self._explain_threat_score(threat_score, vt_intel)
            reputation_reasoning = self._explain_reputation(reputation_status, ipinfo_intel)
            confidence_reasoning = self._explain_confidence(confidence_score, sources_queried)

            # Generate findings summary
            findings_summary = self._generate_findings_summary(findings)

            # Build unified report
            report = UnifiedIntelligenceReport(
                ioc_value=ioc_value,
                ioc_type=ioc_type.value,
                exposure_score=exposure_score,
                threat_score=threat_score,
                risk_level=threat_level,
                reputation_status=reputation_status,
                confidence_score=confidence_score,
                exposure_reasoning=exposure_reasoning,
                threat_reasoning=threat_reasoning,
                reputation_reasoning=reputation_reasoning,
                confidence_reasoning=confidence_reasoning,
                findings=findings,
                findings_summary=findings_summary,
                virustotal=vt_intel,
                shodan=shodan_intel,
                ipinfo=ipinfo_intel,
                sources_queried=sources_queried,
                sources_failed=sources_failed,
                investigation_timestamp=datetime.now(timezone.utc),
                last_updated=datetime.now(timezone.utc),
            )

            logger.info(
                "Unified enrichment completed",
                ioc=ioc_value,
                exposure_score=exposure_score,
                threat_score=threat_score,
                reputation=reputation_status.value,
                sources_count=len(sources_queried),
                findings_count=len(findings)
            )

            return report

        except Exception as exc:
            logger.error("Unified enrichment failed: {}", exc)
            raise

    async def _collect_virustotal(self, ioc_value: str, query_type: str) -> Optional[VirusTotalIntelligence]:
        """Collect VirusTotal intelligence."""
        try:
            rows = await self.vt_connector.collect(ioc_value, query_type)
            if not rows:
                return None

            payload = rows[0].get("payload", {})
            provider = payload.get("provider_payload", {})
            attributes = provider.get("attributes", {}) if isinstance(provider, dict) else {}
            stats = provider.get("analysis_stats", {}) if isinstance(provider, dict) else {}

            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            harmless = int(stats.get("harmless", 0) or 0)
            undetected = int(stats.get("undetected", 0) or 0)
            dns_records = attributes.get("last_dns_records", [])
            related_domains: list[str] = []
            if isinstance(dns_records, list):
                for record in dns_records:
                    if isinstance(record, dict):
                        value = record.get("value")
                        if isinstance(value, str) and value:
                            related_domains.append(value)

            last_modification = attributes.get("last_modification_date")
            last_analysis = None
            if isinstance(last_modification, (int, float)):
                last_analysis = datetime.fromtimestamp(last_modification, tz=timezone.utc)

            return VirusTotalIntelligence(
                reputation=self._determine_vt_reputation(malicious, suspicious, harmless),
                malicious_vendors=malicious,
                suspicious_vendors=suspicious,
                undetected_vendors=undetected,
                harmless_vendors=harmless,
                malware_families=attributes.get("threat_names", []) or [],
                tags=attributes.get("tags", []) or [],
                related_domains=related_domains,
                last_analysis_date=last_analysis,
                raw_response=provider if isinstance(provider, dict) else {},
            )
        except Exception as exc:
            logger.warning("VirusTotal collection error: {}", exc)
            return None

    async def _collect_shodan(self, ioc_value: str, query_type: str) -> Optional[ShodanIntelligence]:
        """Collect Shodan intelligence."""
        try:
            rows = await self.shodan_connector.collect(ioc_value, query_type)
            if not rows:
                return None

            payload = rows[0].get("payload", {})
            provider = payload.get("provider_payload", {})
            if not isinstance(provider, dict):
                return None

            top_match = provider.get("top_match", {})
            if not isinstance(top_match, dict):
                top_match = {}

            vulns = top_match.get("vulns", {})
            cves: list[dict] = []
            if isinstance(vulns, dict):
                cves = [{"cve": key} for key in vulns.keys()]
            elif isinstance(vulns, list):
                cves = [{"cve": str(item)} for item in vulns]

            open_ports = provider.get("open_ports", []) or []
            technologies = []
            if top_match.get("product"):
                technologies.append(str(top_match.get("product")))
            if top_match.get("transport"):
                technologies.append(str(top_match.get("transport")))

            return ShodanIntelligence(
                open_ports=[int(p) for p in open_ports if str(p).isdigit()],
                services=technologies,
                technologies=technologies,
                cves=cves,
                organization=top_match.get("org"),
                asn=top_match.get("asn"),
                country=(top_match.get("location") or {}).get("country_name")
                if isinstance(top_match.get("location"), dict)
                else None,
                city=(top_match.get("location") or {}).get("city")
                if isinstance(top_match.get("location"), dict)
                else None,
                hosting_provider=top_match.get("org"),
                raw_response=provider,
            )
        except Exception as exc:
            logger.warning("Shodan collection error: {}", exc)
            return None

    async def _collect_ipinfo(self, ioc_value: str, query_type: str) -> Optional[IpinfoIntelligence]:
        """Collect IPinfo intelligence."""
        try:
            rows = await self.ipinfo_connector.collect(ioc_value, query_type)
            if not rows:
                return None

            payload = rows[0].get("payload", {})
            provider = payload.get("provider_payload", {})
            if not isinstance(provider, dict):
                return None

            ipinfo_payload = provider.get("ipinfo", {})
            privacy_payload = provider.get("privacy", {})
            if not isinstance(ipinfo_payload, dict):
                ipinfo_payload = {}
            if not isinstance(privacy_payload, dict):
                privacy_payload = {}

            return IpinfoIntelligence(
                asn=ipinfo_payload.get("asn"),
                organization=ipinfo_payload.get("org"),
                country=ipinfo_payload.get("country"),
                country_code=ipinfo_payload.get("country"),
                city=ipinfo_payload.get("city"),
                region=ipinfo_payload.get("region"),
                postal_code=ipinfo_payload.get("postal"),
                timezone=ipinfo_payload.get("timezone"),
                is_vpn=bool(privacy_payload.get("vpn")),
                is_proxy=bool(privacy_payload.get("proxy")),
                is_tor=bool(privacy_payload.get("tor")),
                is_datacenter=bool(privacy_payload.get("hosting")),
                raw_response=provider,
            )
        except Exception as exc:
            logger.warning("IPinfo collection error: {}", exc)
            return None

    def _is_ip_address(self, value: str) -> bool:
        """Check if value is an IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _determine_vt_reputation(self, malicious: int, suspicious: int, harmless: int) -> str:
        """Determine VirusTotal reputation status."""
        if malicious > 0:
            return "Malicious"
        elif suspicious > 0:
            return "Suspicious"
        elif harmless > 0:
            return "Clean"
        else:
            return "Unknown"

    def _correlate_findings(
        self,
        vt_intel: Optional[VirusTotalIntelligence],
        shodan_intel: Optional[ShodanIntelligence],
        ipinfo_intel: Optional[IpinfoIntelligence],
        ioc_value: str
    ) -> list[Finding]:
        """Generate correlated findings from all sources."""
        findings = []

        # VirusTotal findings
        if vt_intel:
            if vt_intel.malicious_vendors > 0:
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS_DETECTION,
                    title="Malicious Detection",
                    description=f"{vt_intel.malicious_vendors} security vendors detected malicious activity",
                    severity=RiskLevelEnum.CRITICAL,
                    source="VirusTotal",
                    confidence=0.95
                ))

            if vt_intel.malware_families:
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS_DETECTION,
                    title="Malware Families Detected",
                    description=f"Associated with malware families: {', '.join(vt_intel.malware_families)}",
                    severity=RiskLevelEnum.HIGH,
                    source="VirusTotal",
                    confidence=0.90
                ))

            if vt_intel.suspicious_vendors > 0:
                findings.append(Finding(
                    finding_type=FindingType.SUSPICIOUS_ACTIVITY,
                    title="Suspicious Activity",
                    description=f"{vt_intel.suspicious_vendors} security vendors flagged as suspicious",
                    severity=RiskLevelEnum.MEDIUM,
                    source="VirusTotal",
                    confidence=0.85
                ))

            if vt_intel.malicious_vendors == 0 and vt_intel.suspicious_vendors == 0:
                findings.append(Finding(
                    finding_type=FindingType.BENIGN,
                    title="No Malicious Detections",
                    description="No security vendors detected malicious or suspicious activity",
                    severity=RiskLevelEnum.INFO,
                    source="VirusTotal",
                    confidence=0.99
                ))

        # Shodan findings
        if shodan_intel and shodan_intel.open_ports:
            findings.append(Finding(
                finding_type=FindingType.VULNERABLE_SERVICE,
                title="Open Ports Detected",
                description=f"Open ports identified: {', '.join(map(str, shodan_intel.open_ports))}",
                severity=RiskLevelEnum.MEDIUM,
                source="Shodan",
                confidence=0.95
            ))

        if shodan_intel and shodan_intel.cves:
            findings.append(Finding(
                finding_type=FindingType.VULNERABLE_SERVICE,
                title="Known Vulnerabilities",
                description=(
                    "Potential vulnerabilities: "
                    + ", ".join(str(cve.get("cve", "unknown")) for cve in shodan_intel.cves[:10])
                ),
                severity=RiskLevelEnum.HIGH,
                source="Shodan",
                confidence=0.85
            ))

        # IPinfo findings
        if ipinfo_intel:
            security_issues = []
            if ipinfo_intel.is_tor:
                security_issues.append("Tor node detected")
            if ipinfo_intel.is_proxy:
                security_issues.append("Proxy detected")
            if ipinfo_intel.is_vpn:
                security_issues.append("VPN detected")

            if security_issues:
                findings.append(Finding(
                    finding_type=FindingType.RISKY_INFRASTRUCTURE,
                    title="Security Flags Detected",
                    description=f"Infrastructure flags: {', '.join(security_issues)}",
                    severity=RiskLevelEnum.MEDIUM,
                    source="IPinfo",
                    confidence=0.90
                ))

        return findings

    def _calculate_exposure_score(
        self,
        shodan_intel: Optional[ShodanIntelligence],
        ipinfo_intel: Optional[IpinfoIntelligence],
        vt_intel: Optional[VirusTotalIntelligence]
    ) -> float:
        """
        Calculate exposure score (internet visibility/attack surface).
        HIGH exposure does NOT mean malicious.
        """
        exposure = 0.0

        # Shodan: open ports increase exposure
        if shodan_intel and shodan_intel.open_ports:
            exposure += min(len(shodan_intel.open_ports) * 3, 40)

        # Shodan: technologies/services increase exposure
        if shodan_intel and shodan_intel.technologies:
            exposure += min(len(shodan_intel.technologies) * 2, 20)

        # Shodan: CVEs increase exposure
        if shodan_intel and shodan_intel.cves:
            exposure += min(len(shodan_intel.cves), 15)

        # IPinfo: public IP with hosting provider = some exposure
        if ipinfo_intel and ipinfo_intel.hosting_type:
            exposure += 10

        # VirusTotal: related domains/IPs indicate complex infrastructure
        if vt_intel:
            related_count = len(vt_intel.related_domains or []) + len(vt_intel.related_ips or [])
            exposure += min(related_count * 1, 15)

        return min(exposure, 100.0)

    def _calculate_threat_score(
        self,
        vt_intel: Optional[VirusTotalIntelligence],
        shodan_intel: Optional[ShodanIntelligence],
        findings: list[Finding]
    ) -> tuple[float, RiskLevelEnum]:
        """
        Calculate threat score (maliciousness/abuse indicators).
        SEPARATE from exposure.
        """
        threat = 0.0

        # VirusTotal: malicious detections are THREAT
        if vt_intel:
            if vt_intel.malicious_vendors > 0:
                threat += min(vt_intel.malicious_vendors * 8, 50)

            if vt_intel.suspicious_vendors > 0:
                threat += min(vt_intel.suspicious_vendors * 3, 20)

            if vt_intel.malware_families:
                threat += min(len(vt_intel.malware_families) * 10, 40)

        # Findings-based threat scoring
        if findings:
            severity_scores = {
                RiskLevelEnum.CRITICAL: 40,
                RiskLevelEnum.HIGH: 25,
                RiskLevelEnum.MEDIUM: 15,
                RiskLevelEnum.LOW: 5,
                RiskLevelEnum.INFO: 0,
            }
            for finding in findings:
                threat += severity_scores.get(finding.severity, 0) * finding.confidence

        threat = min(threat, 100.0)

        # Determine risk level from threat
        if threat >= 80:
            risk_level = RiskLevelEnum.CRITICAL
        elif threat >= 60:
            risk_level = RiskLevelEnum.HIGH
        elif threat >= 40:
            risk_level = RiskLevelEnum.MEDIUM
        elif threat >= 20:
            risk_level = RiskLevelEnum.LOW
        else:
            risk_level = RiskLevelEnum.INFO

        return threat, risk_level

    def _determine_reputation_status(
        self,
        ipinfo_intel: Optional[IpinfoIntelligence],
        vt_intel: Optional[VirusTotalIntelligence],
        shodan_intel: Optional[ShodanIntelligence]
    ) -> ReputationStatus:
        """Determine reputation status from infrastructure indicators."""
        
        # Check for enterprise organizations
        if ipinfo_intel and ipinfo_intel.organization:
            org_lower = ipinfo_intel.organization.lower()
            enterprise_keywords = ['microsoft', 'google', 'amazon', 'apple', 'ibm', 'cisco', 'intel', 'meta', 'adobe']
            if any(kw in org_lower for kw in enterprise_keywords):
                return ReputationStatus.TRUSTED_ENTERPRISE

            if 'cdn' in org_lower or 'cloudflare' in org_lower or 'akamai' in org_lower:
                return ReputationStatus.CDN

            if 'isp' in org_lower:
                return ReputationStatus.TRUSTED_ISP

            if 'hosting' in org_lower or 'provider' in org_lower:
                return ReputationStatus.HOSTING_PROVIDER

        # Check VirusTotal reputation
        if vt_intel:
            if vt_intel.harmless_vendors > vt_intel.malicious_vendors + vt_intel.suspicious_vendors:
                if vt_intel.malicious_vendors == 0 and vt_intel.suspicious_vendors == 0:
                    return ReputationStatus.TRUSTED_ENTERPRISE

            if vt_intel.malicious_vendors > 0:
                return ReputationStatus.MALICIOUS

            if vt_intel.suspicious_vendors > 0:
                return ReputationStatus.SUSPICIOUS

        return ReputationStatus.UNKNOWN

    def _calculate_confidence_score(
        self,
        findings: list[Finding],
        sources_queried: list[str]
    ) -> float:
        """Calculate confidence score (intelligence reliability)."""
        
        # Base: more sources = more confidence
        source_confidence = min(len(sources_queried) / 3.0, 1.0)  # Max 3 sources

        # Findings agreement increases confidence
        findings_confidence = 0.0
        if findings:
            findings_confidence = sum(f.confidence for f in findings) / len(findings)

        # Average confidence
        confidence = (source_confidence + findings_confidence) / 2.0

        return min(max(confidence, 0.0), 1.0)

    def _explain_exposure_score(
        self,
        exposure_score: float,
        shodan_intel: Optional[ShodanIntelligence],
        ipinfo_intel: Optional[IpinfoIntelligence]
    ) -> ScoreExplanation:
        """Generate explanation for exposure score."""
        
        factors = []
        
        if shodan_intel:
            if shodan_intel.open_ports:
                factors.append(f"{len(shodan_intel.open_ports)} open ports detected")
            if shodan_intel.technologies:
                factors.append(f"{len(shodan_intel.technologies)} technologies identified")
            if shodan_intel.cves:
                factors.append(f"{len(shodan_intel.cves)} known vulnerabilities")

        if ipinfo_intel and ipinfo_intel.hosting_type:
            factors.append("Public hosting infrastructure")

        if exposure_score < 30:
            reasoning = "Minimal public exposure detected. Infrastructure is not widely internet-facing."
        elif exposure_score < 60:
            reasoning = "Moderate public exposure. Some services are publicly accessible."
        else:
            reasoning = "High public exposure. Significant internet-facing infrastructure and services detected."

        return ScoreExplanation(
            score=exposure_score,
            reasoning=reasoning,
            key_factors=factors
        )

    def _explain_threat_score(
        self,
        threat_score: float,
        vt_intel: Optional[VirusTotalIntelligence]
    ) -> ScoreExplanation:
        """Generate explanation for threat score."""
        
        factors = []
        
        if vt_intel:
            if vt_intel.malicious_vendors > 0:
                factors.append(f"Malicious detection by {vt_intel.malicious_vendors} vendors")
            if vt_intel.suspicious_vendors > 0:
                factors.append(f"Suspicious detection by {vt_intel.suspicious_vendors} vendors")
            if vt_intel.malware_families:
                factors.append(f"Associated with {len(vt_intel.malware_families)} malware families")
            if vt_intel.harmless_vendors > 0 and vt_intel.malicious_vendors == 0:
                factors.append(f"Benign detection by {vt_intel.harmless_vendors} vendors")

        if threat_score < 20:
            reasoning = "No significant malicious indicators detected. Infrastructure appears legitimate."
        elif threat_score < 50:
            reasoning = "Moderate threat indicators. Some suspicious activity or vulnerabilities detected."
        elif threat_score < 80:
            reasoning = "High threat indicators. Multiple malicious or suspicious detections."
        else:
            reasoning = "Critical threat indicators. Confirmed malicious activity detected."

        return ScoreExplanation(
            score=threat_score,
            reasoning=reasoning,
            key_factors=factors
        )

    def _explain_reputation(
        self,
        reputation_status: ReputationStatus,
        ipinfo_intel: Optional[IpinfoIntelligence]
    ) -> str:
        """Generate explanation for reputation status."""
        
        explanations = {
            ReputationStatus.TRUSTED_ENTERPRISE: "Infrastructure belongs to a known enterprise organization with strong reputation.",
            ReputationStatus.TRUSTED_ISP: "Infrastructure belongs to a trusted ISP provider.",
            ReputationStatus.HOSTING_PROVIDER: "Infrastructure belongs to a known hosting provider.",
            ReputationStatus.CDN: "Infrastructure is part of a CDN network.",
            ReputationStatus.NEUTRAL: "Infrastructure has neutral reputation with no significant indicators.",
            ReputationStatus.SUSPICIOUS: "Infrastructure shows suspicious indicators. Investigation recommended.",
            ReputationStatus.MALICIOUS: "Infrastructure has confirmed malicious reputation.",
            ReputationStatus.UNKNOWN: "Reputation could not be determined from available intelligence.",
        }
        
        return explanations.get(reputation_status, "Unknown reputation status.")

    def _explain_confidence(
        self,
        confidence_score: float,
        sources_queried: list[str]
    ) -> str:
        """Generate explanation for confidence score."""
        
        if confidence_score > 0.9:
            return f"Very high confidence ({confidence_score*100:.0f}%). Intelligence from multiple consistent sources."
        elif confidence_score > 0.7:
            return f"High confidence ({confidence_score*100:.0f}%). Good source agreement."
        elif confidence_score > 0.5:
            return f"Moderate confidence ({confidence_score*100:.0f}%). Some sources agree."
        else:
            return f"Low confidence ({confidence_score*100:.0f}%). Limited data availability."

    def _calculate_unified_score(
        self,
        vt_intel: Optional[VirusTotalIntelligence],
        shodan_intel: Optional[ShodanIntelligence],
        ipinfo_intel: Optional[IpinfoIntelligence],
        findings: list[Finding]
    ) -> tuple[float, RiskLevelEnum, float]:
        """Calculate unified threat score from all sources."""
        threat_score = 0.0
        confidence_score = 0.0

        # Calculate score from findings
        if findings:
            severity_scores = {
                RiskLevelEnum.CRITICAL: 100,
                RiskLevelEnum.HIGH: 70,
                RiskLevelEnum.MEDIUM: 40,
                RiskLevelEnum.LOW: 15,
                RiskLevelEnum.INFO: 5,
            }

            weighted_scores = []
            for finding in findings:
                score = severity_scores.get(finding.severity, 5)
                weighted_scores.append(score * finding.confidence)

            if weighted_scores:
                threat_score = min(sum(weighted_scores) / len(weighted_scores), 100.0)

            # Calculate confidence
            avg_confidence = sum(f.confidence for f in findings) / len(findings)
            confidence_score = avg_confidence

        # Boost score from VirusTotal detections
        if vt_intel and vt_intel.malicious_vendors > 0:
            threat_score = min(threat_score + (vt_intel.malicious_vendors * 5), 100)
            confidence_score = min(confidence_score + 0.05, 1.0)

        # Determine risk level
        if threat_score >= 80:
            risk_level = RiskLevelEnum.CRITICAL
        elif threat_score >= 60:
            risk_level = RiskLevelEnum.HIGH
        elif threat_score >= 40:
            risk_level = RiskLevelEnum.MEDIUM
        elif threat_score >= 20:
            risk_level = RiskLevelEnum.LOW
        else:
            risk_level = RiskLevelEnum.INFO

        return threat_score, risk_level, max(0.0, min(1.0, confidence_score))

    def _generate_findings_summary(self, findings: list[Finding]) -> str:
        """Generate human-readable findings summary."""
        if not findings:
            return "No findings to report."

        summaries = []
        for finding in findings:
            summaries.append(f"- {finding.title}: {finding.description}")

        return "\n".join(summaries)
