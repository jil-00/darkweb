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
                        "source": "external",
                        "evidence": finding.evidence,
                        "confidence": finding.confidence,
                    }
                    for finding in report.findings
                ],
                "findings_summary": report.findings_summary,
                "sources": {
                    "queried_count": len(report.sources_queried),
                    "failed_count": len(report.sources_failed),
                },
                "analyst_notes": analyst_notes or "",
            }
            # Do not include provider-specific payloads or provider names to avoid exposing external sources.
            export_data["intelligence"] = {
                "providers_present_count": len(report.sources_queried),
                "providers_failed_count": len(report.sources_failed),
            }

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
