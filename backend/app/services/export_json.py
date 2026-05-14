"""
JSON Export service for threat intelligence investigations.
Creates structured machine-readable exports for integration and automation.
"""

from io import StringIO
import json
from typing import Optional
from datetime import datetime

from loguru import logger

from app.models.unified_intelligence import UnifiedIntelligenceReport


class JSONExportGenerator:
    """Generate JSON exports from unified threat intelligence."""

    def generate_report(
        self,
        report: UnifiedIntelligenceReport,
        analyst_notes: Optional[str] = None,
        include_raw_responses: bool = True,
        filename: str = "threat_report.json"
    ) -> StringIO:
        """
        Generate JSON export from unified intelligence report.

        Args:
            report: Unified intelligence report
            analyst_notes: Optional analyst comments
            include_raw_responses: Whether to include raw API responses
            filename: Output filename

        Returns:
            StringIO object containing JSON data
        """
        try:
            # Build comprehensive JSON object
            export_data = {
                "export_metadata": {
                    "version": "1.0",
                    "generated_at": datetime.utcnow().isoformat(),
                    "platform": "RJ Intelligence Platform",
                    "platform_subtitle": "Advanced Threat Intelligence & Infrastructure Analysis",
                },
                "investigation": {
                    "target": {
                        "ioc": report.ioc_value,
                        "ioc_type": report.ioc_type,
                    },
                    "scores": {
                        "threat_score": report.threat_score,
                        "confidence_score": report.confidence_score,
                        "risk_level": report.risk_level.value,
                    },
                    "timestamp": report.investigation_timestamp.isoformat(),
                },
                "findings": [
                    {
                        "type": finding.finding_type.value,
                        "title": finding.title,
                        "description": finding.description,
                        "severity": finding.severity.value,
                        "source": finding.source,
                        "evidence": finding.evidence,
                        "confidence": finding.confidence,
                    }
                    for finding in report.findings
                ],
                "findings_summary": report.findings_summary,
                "sources": {
                    "queried": report.sources_queried,
                    "failed": report.sources_failed,
                },
                "analyst_notes": analyst_notes or "",
            }

            # Add VirusTotal intelligence
            if report.virustotal:
                vt = report.virustotal
                export_data["intelligence"] = export_data.get("intelligence", {})
                export_data["intelligence"]["virustotal"] = {
                    "reputation": vt.reputation,
                    "detections": {
                        "malicious": vt.malicious_vendors,
                        "suspicious": vt.suspicious_vendors,
                        "undetected": vt.undetected_vendors,
                        "harmless": vt.harmless_vendors,
                    },
                    "community_score": vt.community_score,
                    "malware_families": vt.malware_families,
                    "categories": vt.categories,
                    "tags": vt.tags,
                    "threat_classifications": vt.threat_classifications,
                    "mitre_techniques": vt.mitre_techniques,
                    "related_domains": vt.related_domains[:10] if vt.related_domains else [],
                    "related_ips": vt.related_ips[:10] if vt.related_ips else [],
                    "detection_engines": vt.detection_engines,
                    "last_analysis_date": vt.last_analysis_date.isoformat() if vt.last_analysis_date else None,
                }
                if include_raw_responses and vt.raw_response:
                    export_data["intelligence"]["virustotal"]["raw_response"] = vt.raw_response

            # Add Shodan intelligence
            if report.shodan:
                shodan = report.shodan
                export_data["intelligence"] = export_data.get("intelligence", {})
                export_data["intelligence"]["shodan"] = {
                    "network": {
                        "open_ports": shodan.open_ports,
                        "asn": shodan.asn,
                        "isp": shodan.isp,
                        "organization": shodan.organization,
                    },
                    "geolocation": {
                        "country": shodan.country,
                        "region": shodan.region,
                        "city": shodan.city,
                        "latitude": shodan.latitude,
                        "longitude": shodan.longitude,
                    },
                    "infrastructure": {
                        "services": shodan.services,
                        "technologies": shodan.technologies,
                        "products": shodan.products,
                        "operating_system": shodan.operating_system,
                        "hosting_provider": shodan.hosting_provider,
                    },
                    "security": {
                        "cves": shodan.cves,
                        "cvss_scores": shodan.cvss_scores,
                        "ssl_valid": shodan.ssl_valid,
                    },
                    "domains": shodan.domains[:20] if shodan.domains else [],
                    "hostnames": shodan.hostnames[:20] if shodan.hostnames else [],
                    "last_seen": shodan.last_seen.isoformat() if shodan.last_seen else None,
                }
                if include_raw_responses and shodan.raw_response:
                    export_data["intelligence"]["shodan"]["raw_response"] = shodan.raw_response

            # Add IPinfo intelligence
            if report.ipinfo:
                ipinfo = report.ipinfo
                export_data["intelligence"] = export_data.get("intelligence", {})
                export_data["intelligence"]["ipinfo"] = {
                    "network": {
                        "asn": ipinfo.asn,
                        "organization": ipinfo.organization,
                        "isp": ipinfo.isp,
                    },
                    "geolocation": {
                        "country": ipinfo.country,
                        "country_code": ipinfo.country_code,
                        "region": ipinfo.region,
                        "city": ipinfo.city,
                        "postal_code": ipinfo.postal_code,
                        "timezone": ipinfo.timezone,
                        "latitude": ipinfo.latitude,
                        "longitude": ipinfo.longitude,
                    },
                    "infrastructure": {
                        "hosting_type": ipinfo.hosting_type,
                        "is_anycast": ipinfo.is_anycast,
                        "network_owner": ipinfo.network_owner,
                    },
                    "privacy_flags": {
                        "is_vpn": ipinfo.is_vpn,
                        "is_proxy": ipinfo.is_proxy,
                        "is_tor": ipinfo.is_tor,
                        "is_datacenter": ipinfo.is_datacenter,
                    },
                }
                if include_raw_responses and ipinfo.raw_response:
                    export_data["intelligence"]["ipinfo"]["raw_response"] = ipinfo.raw_response

            # Convert to JSON
            json_str = json.dumps(export_data, indent=2, default=str)
            json_buffer = StringIO(json_str)
            json_buffer.seek(0)

            logger.info(
                "JSON export generated successfully",
                ioc=report.ioc_value,
                filename=filename,
                size_bytes=len(json_str)
            )

            return json_buffer

        except Exception as exc:
            logger.error("JSON export generation failed: {}", exc)
            raise
