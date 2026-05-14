#!/usr/bin/env python
"""Test new JSON export and explainable findings services."""

from app.services.export_json import JSONExportGenerator
from app.services.explainable_findings import ExplainableFindingsGenerator
from app.models.unified_intelligence import (
    UnifiedIntelligenceReport, VirusTotalIntelligence, FindingType, RiskLevel
)
from datetime import datetime

# Test JSON export generator
json_gen = JSONExportGenerator()
print("JSONExportGenerator instantiated successfully")

# Test findings generator
findings_gen = ExplainableFindingsGenerator()
print("ExplainableFindingsGenerator instantiated successfully")

# Create minimal test report
test_report = UnifiedIntelligenceReport(
    ioc_value="8.8.8.8",
    ioc_type="ipv4",
    threat_score=15.0,
    risk_level=RiskLevel.LOW,
    confidence_score=0.85,
    findings=[],
    findings_summary="Test findings",
    investigation_timestamp=datetime.utcnow(),
    last_updated=datetime.utcnow(),
    sources_queried=["VirusTotal", "Shodan", "IPinfo"],
    sources_failed=[],
)

# Test JSON generation
json_buffer = json_gen.generate_report(test_report, analyst_notes="Test notes")
json_content = json_buffer.getvalue()
print("JSON export generated: " + str(len(json_content)) + " characters")

# Test findings generation
findings = findings_gen.generate_findings(test_report)
print("Explainable findings generated: " + str(len(findings)) + " findings")

# Test reasoning
reasoning = findings_gen.generate_reasoning_explanation(test_report)
print("Reasoning explanation generated with " + str(len(reasoning)) + " components")

print("All service tests passed!")
