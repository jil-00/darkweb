"""
CSV Export service for threat intelligence investigations.
Creates structured CSV reports from unified intelligence data.
"""

from datetime import datetime, timezone
from io import StringIO
from typing import Optional
import csv

from loguru import logger

from app.models.unified_intelligence import UnifiedIntelligenceReport


class CSVExportGenerator:
    """
    Generate CSV reports from unified threat intelligence.
    Supports Excel and standard CSV tools.
    """

    def __init__(self):
        """Initialize CSV export generator."""
        self.fieldnames = [
            "IOC",
            "IOC Type",
            "Exposure Score",
            "Threat Score",
            "Reputation Status",
            "Confidence Score",
            "Risk Level",
            "Findings Count",
            "Findings Summary",
            "VT Malicious Vendors",
            "VT Suspicious Vendors",
            "VT Harmless Vendors",
            "VT Malware Families",
            "VT Reputation",
            "VT Categories",
            "VT Tags",
            "Shodan Open Ports",
            "Shodan Services",
            "Shodan SSL Valid",
            "Shodan Technologies",
            "Shodan CVEs",
            "Shodan Hosting Provider",
            "IPinfo ASN",
            "IPinfo Organization",
            "IPinfo ISP",
            "IPinfo Country",
            "IPinfo City",
            "IPinfo Hosting Type",
            "IPinfo Privacy Flags",
            "Sources Queried",
            "Sources Failed",
            "Investigation Timestamp",
            "Analyst Notes",
        ]

    def _format_list(self, items: Optional[list]) -> str:
        """Format list for CSV export."""
        if not items:
            return ""
        return "; ".join(str(item) for item in items)

    def _format_bool(self, value: Optional[bool]) -> str:
        """Format boolean for CSV export."""
        if value is None:
            return ""
        return "Yes" if value else "No"

    def _extract_row(self, report: UnifiedIntelligenceReport) -> dict:
        """Extract report data into CSV row."""
        row = {
            "IOC": report.ioc_value,
            "IOC Type": report.ioc_type.upper(),
            "Exposure Score": f"{report.exposure_score:.1f}",
            "Threat Score": f"{report.threat_score:.1f}",
            "Reputation Status": report.reputation_status.value,
            "Confidence Score": f"{report.confidence_score*100:.0f}%",
            "Risk Level": report.risk_level.value,
            "Findings Count": len(report.findings),
            "Findings Summary": report.findings_summary[:500] if report.findings_summary else "",
            "VT Malicious Vendors": "",
            "VT Suspicious Vendors": "",
            "VT Harmless Vendors": "",
            "VT Malware Families": "",
            "VT Reputation": "",
            "VT Categories": "",
            "VT Tags": "",
            "Shodan Open Ports": "",
            "Shodan Services": "",
            "Shodan SSL Valid": "",
            "Shodan Technologies": "",
            "Shodan CVEs": "",
            "Shodan Hosting Provider": "",
            "IPinfo ASN": "",
            "IPinfo Organization": "",
            "IPinfo ISP": "",
            "IPinfo Country": "",
            "IPinfo City": "",
            "IPinfo Hosting Type": "",
            "IPinfo Privacy Flags": "",
            "Sources Queried (count)": len(report.sources_queried),
            "Sources Failed": self._format_list(report.sources_failed),
            "Investigation Timestamp": report.investigation_timestamp.isoformat(),
            "Analyst Notes": report.analyst_notes or "",
        }

        # Extract VirusTotal data
        if report.virustotal:
            vt = report.virustotal
            row["VT Malicious Vendors"] = str(vt.malicious_vendors)
            row["VT Suspicious Vendors"] = str(vt.suspicious_vendors)
            row["VT Harmless Vendors"] = str(vt.harmless_vendors)
            row["VT Malware Families"] = self._format_list(vt.malware_families)
            row["VT Reputation"] = vt.reputation or ""
            row["VT Categories"] = self._format_list(vt.categories)
            row["VT Tags"] = self._format_list(vt.tags)

        # Extract Shodan data
        if report.shodan:
            shodan = report.shodan
            row["Shodan Open Ports"] = self._format_list(shodan.open_ports)
            row["Shodan Services"] = self._format_list(shodan.services)
            row["Shodan SSL Valid"] = self._format_bool(shodan.ssl_valid)
            row["Shodan Technologies"] = self._format_list(shodan.technologies)
            row["Shodan CVEs"] = str(len(shodan.cves)) if shodan.cves else "0"
            row["Shodan Hosting Provider"] = shodan.hosting_provider or ""

        # Extract IPinfo data
        if report.ipinfo:
            ipinfo = report.ipinfo
            row["IPinfo ASN"] = ipinfo.asn or ""
            row["IPinfo Organization"] = ipinfo.organization or ""
            row["IPinfo ISP"] = ipinfo.isp or ""
            row["IPinfo Country"] = ipinfo.country or ""
            row["IPinfo City"] = ipinfo.city or ""
            row["IPinfo Hosting Type"] = ipinfo.hosting_type or ""
            
            # Privacy flags
            privacy_flags = []
            if ipinfo.is_vpn:
                privacy_flags.append("VPN")
            if ipinfo.is_proxy:
                privacy_flags.append("Proxy")
            if ipinfo.is_tor:
                privacy_flags.append("Tor")
            if ipinfo.is_datacenter:
                privacy_flags.append("Datacenter")
            row["IPinfo Privacy Flags"] = ";".join(privacy_flags) if privacy_flags else ""

        return row

    def generate_report(
        self,
        report: UnifiedIntelligenceReport,
        analyst_notes: Optional[str] = None,
        filename: str = "threat_report.csv"
    ) -> StringIO:
        """
        Generate CSV report from unified intelligence.

        Args:
            report: Unified intelligence report
            analyst_notes: Optional analyst comments
            filename: Output filename

        Returns:
            StringIO object containing CSV data
        """
        try:
            csv_buffer = StringIO()

            # Create CSV writer
            writer = csv.DictWriter(
                csv_buffer,
                fieldnames=self.fieldnames,
                quoting=csv.QUOTE_MINIMAL,
                lineterminator='\n'
            )

            # Write header
            writer.writeheader()

            # Extract and write row
            row = self._extract_row(report)
            if analyst_notes:
                row["Analyst Notes"] = analyst_notes[:1000]

            writer.writerow(row)

            csv_buffer.seek(0)

            logger.info(
                "CSV report generated successfully",
                ioc=report.ioc_value,
                filename=filename
            )

            return csv_buffer

        except Exception as exc:
            logger.error("CSV report generation failed: {}", exc)
            raise

    def generate_batch_report(
        self,
        reports: list[UnifiedIntelligenceReport],
        filename: str = "threat_reports_batch.csv"
    ) -> StringIO:
        """
        Generate batch CSV report from multiple investigations.

        Args:
            reports: List of unified intelligence reports
            filename: Output filename

        Returns:
            StringIO object containing CSV data
        """
        try:
            csv_buffer = StringIO()

            # Create CSV writer
            writer = csv.DictWriter(
                csv_buffer,
                fieldnames=self.fieldnames,
                quoting=csv.QUOTE_MINIMAL,
                lineterminator='\n'
            )

            # Write header
            writer.writeheader()

            # Write rows
            for report in reports:
                row = self._extract_row(report)
                writer.writerow(row)

            csv_buffer.seek(0)

            logger.info(
                "Batch CSV report generated successfully",
                report_count=len(reports),
                filename=filename
            )

            return csv_buffer

        except Exception as exc:
            logger.error("Batch CSV report generation failed: {}", exc)
            raise
