"""
Explainable findings generator for threat intelligence analysis.
Generates human-readable explanations for all threat determinations.
"""

from typing import Optional
from loguru import logger

from app.models.unified_intelligence import (
    UnifiedIntelligenceReport, Finding, FindingType, RiskLevel, VirusTotalIntelligence,
    ShodanIntelligence, IpinfoIntelligence
)


class ExplainableFindingsGenerator:
    """
    Generate explainable findings with reasoning from unified intelligence.
    Provides transparency into threat determinations and scoring.
    """

    def __init__(self):
        """Initialize findings generator."""
        self.risk_descriptions = {
            RiskLevel.CRITICAL: "Critical risk - immediate investigation required",
            RiskLevel.HIGH: "High risk - urgent investigation recommended",
            RiskLevel.MEDIUM: "Medium risk - investigation recommended",
            RiskLevel.LOW: "Low risk - monitoring recommended",
            RiskLevel.INFO: "Informational - no immediate risk",
        }

    def generate_findings(self, report: UnifiedIntelligenceReport) -> list[Finding]:
        """
        Generate comprehensive explainable findings from intelligence sources.

        Args:
            report: Unified intelligence report

        Returns:
            List of Finding objects with reasoning
        """
        findings = []

        # Generate VirusTotal findings
        if report.virustotal:
            findings.extend(self._generate_virustotal_findings(report.virustotal))

        # Generate Shodan findings
        if report.shodan:
            findings.extend(self._generate_shodan_findings(report.shodan))

        # Generate IPinfo findings
        if report.ipinfo:
            findings.extend(self._generate_ipinfo_findings(report.ipinfo))

        # Generate correlation findings
        findings.extend(self._generate_correlation_findings(report))

        return findings

    def _generate_virustotal_findings(self, vt: VirusTotalIntelligence) -> list[Finding]:
        """Generate findings from VirusTotal intelligence."""
        findings = []

        # Malicious detections
        if vt.malicious_vendors > 0:
            findings.append(Finding(
                finding_type=FindingType.MALICIOUS_DETECTION,
                title=f"Malicious Detection: {vt.malicious_vendors} Vendor(s)",
                description=f"{vt.malicious_vendors} security vendors detected malicious activity. "
                           f"Harmless: {vt.harmless_vendors}, Suspicious: {vt.suspicious_vendors}, "
                           f"Undetected: {vt.undetected_vendors}",
                severity=RiskLevel.CRITICAL,
                source="VirusTotal",
                evidence=f"Detected by vendors: {', '.join(list(vt.detection_engines.keys())[:5])}",
                confidence=0.95
            ))

        # Suspicious detections
        elif vt.suspicious_vendors > 0:
            findings.append(Finding(
                finding_type=FindingType.SUSPICIOUS_ACTIVITY,
                title=f"Suspicious Detection: {vt.suspicious_vendors} Vendor(s)",
                description=f"{vt.suspicious_vendors} security vendors flagged as suspicious. "
                           f"Harmless: {vt.harmless_vendors}, Undetected: {vt.undetected_vendors}",
                severity=RiskLevel.MEDIUM,
                source="VirusTotal",
                evidence=f"Suspicious flags from vendors analyzing: {', '.join(list(vt.detection_engines.keys())[:3])}",
                confidence=0.80
            ))

        # Malware families
        if vt.malware_families:
            families_str = ", ".join(vt.malware_families[:5])
            findings.append(Finding(
                finding_type=FindingType.MALICIOUS_DETECTION,
                title="Malware Family Association",
                description=f"Associated with malware families: {families_str}. "
                           f"These are known malicious code families tracked across the threat landscape.",
                severity=RiskLevel.HIGH,
                source="VirusTotal",
                evidence=f"Malware families: {families_str}",
                confidence=0.90
            ))

        # Threat classifications
        if vt.threat_classifications:
            findings.append(Finding(
                finding_type=FindingType.MALICIOUS_DETECTION,
                title="Threat Classification",
                description=f"Classified as: {', '.join(vt.threat_classifications)}. "
                           f"This represents the type of threat associated with this IOC.",
                severity=RiskLevel.HIGH,
                source="VirusTotal",
                evidence=f"Classifications: {', '.join(vt.threat_classifications)}",
                confidence=0.85
            ))

        # MITRE ATT&CK techniques
        if vt.mitre_techniques:
            findings.append(Finding(
                finding_type=FindingType.MALICIOUS_DETECTION,
                title="MITRE ATT&CK Techniques Detected",
                description=f"Associated with MITRE ATT&CK techniques: {', '.join(vt.mitre_techniques[:3])}. "
                           f"These are known adversary tactics and techniques.",
                severity=RiskLevel.HIGH,
                source="VirusTotal",
                evidence=f"MITRE techniques: {', '.join(vt.mitre_techniques[:3])}",
                confidence=0.88
            ))

        # Community votes
        if vt.community_score is not None:
            if vt.community_score > 0:
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS_DETECTION,
                    title="Community Votes: Malicious",
                    description=f"VirusTotal community voted this as malicious with score {vt.community_score}",
                    severity=RiskLevel.MEDIUM,
                    source="VirusTotal",
                    evidence=f"Community score: {vt.community_score}",
                    confidence=0.70
                ))
            elif vt.community_score < 0:
                findings.append(Finding(
                    finding_type=FindingType.BENIGN,
                    title="Community Votes: Benign",
                    description=f"VirusTotal community voted this as benign with score {vt.community_score}",
                    severity=RiskLevel.INFO,
                    source="VirusTotal",
                    evidence=f"Community score: {vt.community_score}",
                    confidence=0.70
                ))

        # Clean status
        if vt.malicious_vendors == 0 and vt.suspicious_vendors == 0 and not vt.malware_families:
            findings.append(Finding(
                finding_type=FindingType.BENIGN,
                title="No Malicious Detections",
                description=f"No malicious or suspicious activity detected by {vt.harmless_vendors} vendors. "
                           f"All analyzed samples returned harmless verdicts.",
                severity=RiskLevel.INFO,
                source="VirusTotal",
                evidence=f"Analyzed by {vt.harmless_vendors} vendors with 0 malicious, 0 suspicious detections",
                confidence=0.99
            ))

        # Categories
        if vt.categories:
            findings.append(Finding(
                finding_type=FindingType.SUSPICIOUS_ACTIVITY,
                title="Content Categories",
                description=f"Categorized as: {', '.join(vt.categories[:3])}. "
                           f"These categories help identify the type of content or infrastructure.",
                severity=RiskLevel.LOW,
                source="VirusTotal",
                evidence=f"Categories: {', '.join(vt.categories)}",
                confidence=0.80
            ))

        return findings

    def _generate_shodan_findings(self, shodan: ShodanIntelligence) -> list[Finding]:
        """Generate findings from Shodan intelligence."""
        findings = []

        # Open ports
        if shodan.open_ports:
            findings.append(Finding(
                finding_type=FindingType.VULNERABLE_SERVICE,
                title=f"Open Ports Detected: {len(shodan.open_ports)}",
                description=f"Found {len(shodan.open_ports)} open ports: {', '.join(map(str, shodan.open_ports[:10]))}. "
                           f"Open ports indicate exposed services and potential attack surface.",
                severity=RiskLevel.MEDIUM,
                source="Shodan",
                evidence=f"Ports: {', '.join(map(str, shodan.open_ports))}",
                confidence=0.95
            ))

        # CVEs
        if shodan.cves:
            cve_count = len(shodan.cves)
            max_cvss = max([cve.get('cvss', 0) for cve in shodan.cves]) if shodan.cves else 0
            severity = RiskLevel.HIGH if max_cvss >= 7 else RiskLevel.MEDIUM
            findings.append(Finding(
                finding_type=FindingType.VULNERABLE_SERVICE,
                title=f"Known Vulnerabilities: {cve_count} CVEs",
                description=f"Found {cve_count} known vulnerabilities. Maximum CVSS score: {max_cvss}. "
                           f"These vulnerabilities could be exploited if the services are not patched.",
                severity=severity,
                source="Shodan",
                evidence=f"CVEs: {', '.join([cve.get('id', 'Unknown') for cve in shodan.cves[:5]])}",
                confidence=0.92
            ))

        # SSL/TLS issues
        if shodan.ssl_valid is False:
            findings.append(Finding(
                finding_type=FindingType.VULNERABLE_SERVICE,
                title="Invalid SSL/TLS Certificate",
                description="The SSL/TLS certificate is invalid. This could indicate self-signed certificates, "
                           "expired certificates, or misconfigurations that could affect secure communication.",
                severity=RiskLevel.MEDIUM,
                source="Shodan",
                evidence="SSL certificate validation failed",
                confidence=0.90
            ))

        # Technologies
        if shodan.technologies:
            findings.append(Finding(
                finding_type=FindingType.RISKY_INFRASTRUCTURE,
                title=f"Technologies: {len(shodan.technologies)} Identified",
                description=f"Identified technologies: {', '.join(shodan.technologies[:5])}. "
                           f"Understanding the software stack helps identify potential vulnerabilities.",
                severity=RiskLevel.LOW,
                source="Shodan",
                evidence=f"Technologies: {', '.join(shodan.technologies)}",
                confidence=0.85
            ))

        # Hosting provider
        if shodan.hosting_provider:
            findings.append(Finding(
                finding_type=FindingType.RISKY_INFRASTRUCTURE,
                title=f"Hosting Provider: {shodan.hosting_provider}",
                description=f"Infrastructure hosted by {shodan.hosting_provider}. "
                           f"Enterprise hosting providers typically have better security practices.",
                severity=RiskLevel.INFO,
                source="Shodan",
                evidence=f"Hosting: {shodan.hosting_provider}",
                confidence=0.85
            ))

        return findings

    def _generate_ipinfo_findings(self, ipinfo: IpinfoIntelligence) -> list[Finding]:
        """Generate findings from IPinfo intelligence."""
        findings = []

        # Privacy flags
        security_issues = []
        if ipinfo.is_tor:
            security_issues.append("Tor exit node")
        if ipinfo.is_proxy:
            security_issues.append("Proxy service")
        if ipinfo.is_vpn:
            security_issues.append("VPN provider")
        if ipinfo.is_datacenter and not ipinfo.is_tor and not ipinfo.is_vpn and not ipinfo.is_proxy:
            security_issues.append("Datacenter infrastructure")

        if security_issues:
            severity = RiskLevel.HIGH if "Tor" in security_issues else RiskLevel.MEDIUM
            findings.append(Finding(
                finding_type=FindingType.RISKY_INFRASTRUCTURE,
                title="Privacy/Anonymity Infrastructure",
                description=f"Infrastructure identified as: {', '.join(security_issues)}. "
                           f"These flags indicate anonymization or proxy services.",
                severity=severity,
                source="IPinfo",
                evidence=f"Flags: {', '.join(security_issues)}",
                confidence=0.90
            ))

        # Enterprise infrastructure
        if ipinfo.organization and "Microsoft" in ipinfo.organization or "Google" in ipinfo.organization or "Amazon" in ipinfo.organization:
            findings.append(Finding(
                finding_type=FindingType.TRUSTED_ENTITY,
                title=f"Enterprise Infrastructure: {ipinfo.organization}",
                description=f"Infrastructure belonging to enterprise organization {ipinfo.organization}. "
                           f"Large enterprises naturally have extensive public infrastructure.",
                severity=RiskLevel.INFO,
                source="IPinfo",
                evidence=f"Organization: {ipinfo.organization}",
                confidence=0.95
            ))

        # Geographic information
        if ipinfo.country:
            findings.append(Finding(
                finding_type=FindingType.RISKY_INFRASTRUCTURE,
                title=f"Geolocation: {ipinfo.country}",
                description=f"Infrastructure located in {ipinfo.country}. Geographic location can help identify "
                           f"infrastructure jurisdiction and risk profile.",
                severity=RiskLevel.INFO,
                source="IPinfo",
                evidence=f"Country: {ipinfo.country}, City: {ipinfo.city}",
                confidence=0.85
            ))

        return findings

    def _generate_correlation_findings(self, report: UnifiedIntelligenceReport) -> list[Finding]:
        """Generate correlation-based findings."""
        findings = []

        # Consistency analysis
        if report.virustotal and report.shodan and report.ipinfo:
            findings.append(Finding(
                finding_type=FindingType.SUSPICIOUS_ACTIVITY,
                title="Complete Intelligence Profile",
                description="Complete intelligence available from all three sources (VirusTotal, Shodan, IPinfo). "
                           "Full visibility enables comprehensive threat analysis.",
                severity=RiskLevel.INFO,
                source="Correlation",
                evidence="All sources queried successfully",
                confidence=0.95
            ))

        # Source consistency
        if len(report.sources_failed) > 0:
            findings.append(Finding(
                finding_type=FindingType.SUSPICIOUS_ACTIVITY,
                title=f"Partial Intelligence: {len(report.sources_failed)} source(s) failed",
                description=f"Could not retrieve data from: {', '.join(report.sources_failed)}. "
                           f"Analysis is based on available sources only.",
                severity=RiskLevel.INFO,
                source="Correlation",
                evidence=f"Failed sources: {', '.join(report.sources_failed)}",
                confidence=0.90
            ))

        # Risk summary
        risk_text = self.risk_descriptions.get(report.risk_level, "Unknown risk")
        findings.append(Finding(
            finding_type=FindingType.SUSPICIOUS_ACTIVITY,
            title=f"Risk Assessment: {report.risk_level.value}",
            description=f"{risk_text} based on threat score {report.threat_score:.1f}/100 "
                       f"and confidence {report.confidence_score*100:.0f}%",
            severity=report.risk_level,
            source="Correlation",
            evidence=f"Threat Score: {report.threat_score:.1f}, Confidence: {report.confidence_score*100:.0f}%",
            confidence=report.confidence_score
        ))

        return findings

    def generate_reasoning_explanation(self, report: UnifiedIntelligenceReport) -> dict:
        """
        Generate explanation for threat determination.

        Returns:
            Dictionary with detailed reasoning
        """
        reasoning = {
            "threat_score_reasoning": self._explain_threat_score(report),
            "confidence_reasoning": self._explain_confidence(report),
            "risk_level_reasoning": self._explain_risk_level(report),
            "key_factors": self._extract_key_factors(report),
        }
        return reasoning

    def _explain_threat_score(self, report: UnifiedIntelligenceReport) -> str:
        """Explain threat score determination."""
        if report.virustotal and report.virustotal.malicious_vendors > 0:
            return (f"Threat Score {report.threat_score:.1f}/100 is HIGH because "
                   f"{report.virustotal.malicious_vendors} security vendors detected malicious activity. "
                   f"Malware families: {', '.join(report.virustotal.malware_families) if report.virustotal.malware_families else 'None detected'}")

        if report.shodan and len(report.shodan.cves) > 0:
            max_cvss = max([cve.get('cvss', 0) for cve in report.shodan.cves])
            return (f"Threat Score {report.threat_score:.1f}/100 reflects {len(report.shodan.cves)} known vulnerabilities "
                   f"with maximum CVSS {max_cvss}. These unpatched services increase exploit risk.")

        if report.ipinfo and report.ipinfo.is_tor:
            return (f"Threat Score {report.threat_score:.1f}/100 reflects Tor exit node infrastructure, "
                   f"commonly used for anonymity and potentially malicious activity.")

        return (f"Threat Score {report.threat_score:.1f}/100 is based on combined analysis "
               f"of detection counts, malware associations, and infrastructure risk indicators.")

    def _explain_confidence(self, report: UnifiedIntelligenceReport) -> str:
        """Explain confidence score."""
        if report.confidence_score > 0.9:
            return f"Confidence {report.confidence_score*100:.0f}% is very high due to multiple consistent indicators across sources."
        elif report.confidence_score > 0.7:
            return f"Confidence {report.confidence_score*100:.0f}% is good with multiple sources providing consistent data."
        elif report.confidence_score > 0.5:
            return f"Confidence {report.confidence_score*100:.0f}% is moderate - some sources may have incomplete data."
        else:
            return f"Confidence {report.confidence_score*100:.0f}% is low - limited data available from sources."

    def _explain_risk_level(self, report: UnifiedIntelligenceReport) -> str:
        """Explain risk level determination."""
        explanations = {
            RiskLevel.CRITICAL: "Risk is CRITICAL due to confirmed malicious detections from multiple vendors.",
            RiskLevel.HIGH: "Risk is HIGH due to malware associations, vulnerabilities, or suspicious infrastructure.",
            RiskLevel.MEDIUM: "Risk is MEDIUM due to open services, suspicious flags, or limited detections.",
            RiskLevel.LOW: "Risk is LOW with minimal malicious indicators detected.",
            RiskLevel.INFO: "Risk is INFO - infrastructure is likely legitimate without malicious indicators.",
        }
        return explanations.get(report.risk_level, "Unknown risk level")

    def _extract_key_factors(self, report: UnifiedIntelligenceReport) -> list[str]:
        """Extract key factors influencing the assessment."""
        factors = []

        if report.virustotal and report.virustotal.malicious_vendors > 0:
            factors.append(f"Malicious detection by {report.virustotal.malicious_vendors} vendors")

        if report.virustotal and report.virustotal.malware_families:
            factors.append(f"Associated with {len(report.virustotal.malware_families)} malware families")

        if report.shodan and report.shodan.cves:
            factors.append(f"Exposed to {len(report.shodan.cves)} known vulnerabilities")

        if report.shodan and report.shodan.open_ports:
            factors.append(f"{len(report.shodan.open_ports)} open ports detected")

        if report.ipinfo and report.ipinfo.is_tor:
            factors.append("Tor exit node infrastructure")

        if report.ipinfo and report.ipinfo.organization:
            if any(org in report.ipinfo.organization for org in ["Microsoft", "Google", "Amazon", "Apple"]):
                factors.append("Enterprise infrastructure provider")

        if not factors:
            factors.append("Clean infrastructure with no malicious indicators")

        return factors
