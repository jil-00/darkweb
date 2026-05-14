"""
PDF report generation service for threat intelligence investigations.
Builds a clean, analyst-friendly report layout for exports.
"""

from datetime import datetime, timezone
from io import BytesIO
from typing import Optional

from loguru import logger
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models.unified_intelligence import UnifiedIntelligenceReport, RiskLevel


class PDFReportGenerator:
    """Generate polished PDF investigation reports from unified intelligence."""

    COLOR_NAVY = colors.HexColor("#0F172A")
    COLOR_SLATE = colors.HexColor("#334155")
    COLOR_MUTED = colors.HexColor("#64748B")
    COLOR_BG = colors.HexColor("#F8FAFC")
    COLOR_BORDER = colors.HexColor("#CBD5E1")
    COLOR_HEADER = colors.HexColor("#1D4ED8")
    COLOR_CRITICAL = colors.HexColor("#DC2626")
    COLOR_HIGH = colors.HexColor("#EA580C")
    COLOR_MEDIUM = colors.HexColor("#D97706")
    COLOR_LOW = colors.HexColor("#16A34A")
    COLOR_INFO = colors.HexColor("#2563EB")

    def __init__(self) -> None:
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self) -> None:
        self.styles.add(
            ParagraphStyle(
                name="ReportTitle",
                parent=self.styles["Heading1"],
                fontName="Helvetica-Bold",
                fontSize=24,
                leading=28,
                textColor=self.COLOR_NAVY,
                spaceAfter=6,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ReportSubtitle",
                parent=self.styles["Normal"],
                fontName="Helvetica",
                fontSize=10,
                leading=14,
                textColor=self.COLOR_MUTED,
                spaceAfter=2,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SectionTitle",
                parent=self.styles["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=13,
                leading=16,
                textColor=self.COLOR_NAVY,
                spaceBefore=10,
                spaceAfter=8,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="Body",
                parent=self.styles["Normal"],
                fontName="Helvetica",
                fontSize=10,
                leading=14,
                textColor=self.COLOR_SLATE,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="Small",
                parent=self.styles["Normal"],
                fontName="Helvetica",
                fontSize=9,
                leading=12,
                textColor=self.COLOR_MUTED,
            )
        )

    def _risk_color(self, level: RiskLevel) -> colors.Color:
        mapping = {
            RiskLevel.CRITICAL: self.COLOR_CRITICAL,
            RiskLevel.HIGH: self.COLOR_HIGH,
            RiskLevel.MEDIUM: self.COLOR_MEDIUM,
            RiskLevel.LOW: self.COLOR_LOW,
            RiskLevel.INFO: self.COLOR_INFO,
        }
        return mapping.get(level, self.COLOR_INFO)

    def _score_badge(self, label: str, value: str, accent: colors.Color) -> Table:
        table = Table([[label, value]], colWidths=[1.7 * inch, 1.2 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#EFF6FF")),
                    ("BACKGROUND", (1, 0), (1, 0), colors.white),
                    ("TEXTCOLOR", (0, 0), (0, 0), self.COLOR_SLATE),
                    ("TEXTCOLOR", (1, 0), (1, 0), accent),
                    ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (0, 0), 9),
                    ("FONTSIZE", (1, 0), (1, 0), 16),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                    ("BOX", (0, 0), (-1, -1), 0.75, self.COLOR_BORDER),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, self.COLOR_BORDER),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        return table

    def _kv_table(self, rows: list[tuple[str, str]], left_width: float = 1.9) -> Table:
        table = Table(rows, colWidths=[left_width * inch, (6.9 - left_width) * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
                    ("TEXTCOLOR", (0, 0), (0, -1), self.COLOR_NAVY),
                    ("TEXTCOLOR", (1, 0), (1, -1), self.COLOR_SLATE),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9.5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.5, self.COLOR_BORDER),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        return table

    def _build_header(self, report: UnifiedIntelligenceReport) -> list:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        rows = [
            ("Target IOC", report.ioc_value),
            ("IOC Type", report.ioc_type.upper()),
            ("Risk Level", report.risk_level.value),
            ("Reputation", report.reputation_status.value),
            ("Generated", now),
        ]
        return [
            Paragraph("RJ Intelligence Investigation Report", self.styles["ReportTitle"]),
            Paragraph("Advanced Threat Intelligence & Infrastructure Analysis", self.styles["ReportSubtitle"]),
            Paragraph(f"Report ID: {report.ioc_value} | UTC Timestamp: {now}", self.styles["Small"]),
            Spacer(1, 0.15 * inch),
            self._kv_table(rows, left_width=1.6),
            Spacer(1, 0.2 * inch),
        ]

    def _build_scores(self, report: UnifiedIntelligenceReport) -> list:
        confidence_pct = report.confidence_score * 100.0
        badges = [
            self._score_badge("EXPOSURE", f"{report.exposure_score:.1f}", self.COLOR_CRITICAL),
            self._score_badge("THREAT", f"{report.threat_score:.1f}", self.COLOR_HIGH),
            self._score_badge("CONFIDENCE", f"{confidence_pct:.0f}%", self.COLOR_LOW),
            self._score_badge("SOURCES", str(len(report.sources_queried)), self.COLOR_INFO),
        ]
        grid = Table([[badges[0], badges[1]], [badges[2], badges[3]]], colWidths=[3.45 * inch, 3.45 * inch])
        grid.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )

        blocks: list = [Paragraph("Threat Assessment Overview", self.styles["SectionTitle"]), grid]
        if report.exposure_reasoning:
            blocks.append(Paragraph(f"<b>Exposure Analysis:</b> {report.exposure_reasoning.reasoning}", self.styles["Body"]))
        if report.threat_reasoning:
            blocks.append(Paragraph(f"<b>Threat Analysis:</b> {report.threat_reasoning.reasoning}", self.styles["Body"]))
        if report.reputation_reasoning:
            blocks.append(Paragraph(f"<b>Reputation Insight:</b> {report.reputation_reasoning}", self.styles["Body"]))
        if report.confidence_reasoning:
            blocks.append(Paragraph(f"<b>Confidence Insight:</b> {report.confidence_reasoning}", self.styles["Body"]))
        blocks.append(Spacer(1, 0.15 * inch))
        return blocks

    def _build_findings(self, report: UnifiedIntelligenceReport) -> list:
        blocks: list = [Paragraph("Correlated Findings", self.styles["SectionTitle"])]
        if report.findings_summary:
            blocks.append(Paragraph(report.findings_summary, self.styles["Body"]))
            blocks.append(Spacer(1, 0.06 * inch))

        if not report.findings:
            blocks.append(
                Paragraph(
                    "No direct high-confidence findings were returned for this IOC. "
                    "This can indicate benign infrastructure or low provider coverage.",
                    self.styles["Body"],
                )
            )
            blocks.append(Spacer(1, 0.12 * inch))
            return blocks

        for idx, finding in enumerate(report.findings, start=1):
            sev_color = self._risk_color(finding.severity)
            header = (
                f"<b>{idx}. {finding.title}</b> "
                f"<font color='{sev_color.hexval()}'>[{finding.severity.value}]</font>"
            )
            blocks.append(Paragraph(header, self.styles["Body"]))
            blocks.append(Paragraph(finding.description, self.styles["Body"]))
            blocks.append(
                Paragraph(
                    f"Source: External | Confidence: {finding.confidence * 100:.0f}%",
                    self.styles["Small"],
                )
            )
            if finding.evidence:
                blocks.append(Paragraph(f"Evidence: {finding.evidence}", self.styles["Small"]))
            blocks.append(Spacer(1, 0.08 * inch))
        blocks.append(Spacer(1, 0.08 * inch))
        return blocks

    def _build_source_rows(self, report: UnifiedIntelligenceReport) -> list[tuple[str, str]]:
        rows: list[tuple[str, str]] = []
        if report.virustotal:
            vt = report.virustotal
            rows.append(("VirusTotal Reputation", vt.reputation or "Unknown"))
            rows.append(("VirusTotal Detections", f"Malicious {vt.malicious_vendors}, Suspicious {vt.suspicious_vendors}"))
            if vt.malware_families:
                rows.append(("Malware Families", ", ".join(vt.malware_families[:8])))
        if report.shodan:
            sh = report.shodan
            rows.append(("Shodan Open Ports", ", ".join(str(p) for p in sh.open_ports[:12]) or "None"))
            rows.append(("Shodan Services", ", ".join(sh.services[:8]) or "None"))
            if sh.cves:
                rows.append(("Shodan CVEs", ", ".join(str(row.get("cve") or row.get("id") or "unknown") for row in sh.cves[:8])))
            if sh.organization:
                rows.append(("Shodan Organization", sh.organization))
        if report.ipinfo:
            ip = report.ipinfo
            rows.append(("IPinfo ASN", ip.asn or "Unknown"))
            rows.append(("IPinfo Organization", ip.organization or "Unknown"))
            rows.append(("IPinfo Country", ip.country or "Unknown"))
            flags = []
            if ip.is_vpn:
                flags.append("vpn")
            if ip.is_proxy:
                flags.append("proxy")
            if ip.is_tor:
                flags.append("tor")
            if ip.is_datacenter:
                flags.append("datacenter")
            rows.append(("IPinfo Flags", ", ".join(flags) if flags else "None"))
        if not rows:
            rows.append(("Source Data", "No structured provider response available"))
        return rows

    def _build_sources(self, report: UnifiedIntelligenceReport) -> list:
        # Only include provider counts to avoid exposing provider identities in exports
        queried_count = str(len(report.sources_queried))
        failed_count = str(len(report.sources_failed))
        rows = [("Queried Sources (count)", queried_count), ("Failed Sources (count)", failed_count), ("Provider telemetry", "Omitted to preserve privacy")]
        return [Paragraph("Source Telemetry", self.styles["SectionTitle"]), self._kv_table(rows), Spacer(1, 0.16 * inch)]

    def _build_footer(self, report: UnifiedIntelligenceReport, analyst_notes: Optional[str]) -> list:
        blocks: list = []
        if analyst_notes:
            blocks.append(Paragraph("Analyst Notes", self.styles["SectionTitle"]))
            blocks.append(Paragraph(analyst_notes, self.styles["Body"]))
            blocks.append(Spacer(1, 0.1 * inch))
        blocks.append(
            Paragraph(
                "Generated by RJ Intelligence Platform for defensive investigation workflows.",
                self.styles["Small"],
            )
        )
        blocks.append(
            Paragraph(
                f"Investigation timestamp: {report.investigation_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                self.styles["Small"],
            )
        )
        return blocks

    def generate_report(
        self,
        report: UnifiedIntelligenceReport,
        analyst_notes: Optional[str] = None,
        filename: str = "threat_report.pdf",
    ) -> BytesIO:
        """Generate a complete PDF report and return it as an in-memory buffer."""
        try:
            buffer = BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=letter,
                rightMargin=0.45 * inch,
                leftMargin=0.45 * inch,
                topMargin=0.45 * inch,
                bottomMargin=0.45 * inch,
                title=f"RJ Intelligence Report - {report.ioc_value}",
            )

            story: list = []
            story.extend(self._build_header(report))
            story.extend(self._build_scores(report))
            story.extend(self._build_findings(report))
            story.extend(self._build_sources(report))
            story.extend(self._build_footer(report, analyst_notes))

            doc.build(story)
            buffer.seek(0)

            logger.info(
                "PDF report generated successfully",
                ioc=report.ioc_value,
                filename=filename,
                size_bytes=len(buffer.getvalue()),
            )
            return buffer
        except Exception as exc:
            logger.error("PDF report generation failed: {}", exc)
            raise
