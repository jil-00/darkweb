from datetime import datetime, timezone
from io import BytesIO

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, StreamingResponse
from loguru import logger
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.threat_intel import EnrichmentRequest, EnrichmentResponse
from app.models.unified_intelligence import UnifiedIntelligenceReport, ExportRequest
from app.services.correlation_engine import CorrelationEngine
from app.services.ioc_enrichment import IOCEnrichmentEngine
from app.services.unified_intelligence import UnifiedIntelligenceService
from app.services.export_pdf import PDFReportGenerator
from app.services.export_csv import CSVExportGenerator
from app.services.export_json import JSONExportGenerator
from app.services.explainable_findings import ExplainableFindingsGenerator

router = APIRouter(prefix="/threat-intel", tags=["RJ Intelligence - Threat Investigation"])
enrichment_engine = IOCEnrichmentEngine()
unified_service = UnifiedIntelligenceService()
pdf_generator = PDFReportGenerator()
csv_generator = CSVExportGenerator()
json_generator = JSONExportGenerator()
findings_generator = ExplainableFindingsGenerator()


@router.post("/enrich", response_model=EnrichmentResponse)
async def enrich_ioc(
    request: EnrichmentRequest,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Enrich an IOC with threat intelligence from multiple sources."""
    try:
        response = await enrichment_engine.enrich_ioc(request)

        # Store minimal source metadata (counts only) to avoid leaking provider identities
        await db.enrichments.insert_one({
            "user_id": str(user["_id"]),
            "ioc_value": request.ioc_value,
            "ioc_type": response.ioc.ioc_type.value if response.ioc else None,
            "threat_level": response.ioc.threat_level.value if response.ioc else None,
            "risk_score": response.ioc.risk_score if response.ioc else None,
            "sources_count": len(response.sources_queried),
            "status": response.status,
            "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        })

        logger.info(
            "IOC enriched: user={}, ioc={}, status={}",
            user["email"],
            request.ioc_value,
            response.status,
        )

        return response

    except Exception as exc:
        logger.error("IOC enrichment failed: {}", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="IOC enrichment failed",
        ) from exc


@router.get("/enrichments")
async def get_enrichments(
    limit: int = 20,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Retrieve user's enrichment history."""
    cursor = (
        db.enrichments.find({"user_id": str(user["_id"])})
        .sort("created_at", -1)
        .limit(max(1, min(100, limit)))
    )

    records = []
    async for item in cursor:
        records.append({
            "id": str(item.get("_id")),
            "ioc_value": item["ioc_value"],
            "ioc_type": item.get("ioc_type"),
            "threat_level": item.get("threat_level"),
            "risk_score": item.get("risk_score"),
            "status": item["status"],
            "sources_count": item.get("sources_count", 0),
            "created_at": item["created_at"],
        })

    return records


@router.post("/batch-enrich")
async def batch_enrich_iocs(
    requests: list[EnrichmentRequest],
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Batch enrich multiple IOCs."""
    if len(requests) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 100 IOCs per batch",
        )

    responses = []
    for request in requests:
        try:
            response = await enrichment_engine.enrich_ioc(request)
            responses.append(response)
        except Exception as exc:
            logger.warning("Batch enrichment failed for IOC {}: {}", request.ioc_value, exc)
            continue

    logger.info(
        "batch enriched: user={}, count={}, succeeded={}",
        user["email"],
        len(requests),
        len(responses),
    )

    return {"total": len(requests), "enriched": len(responses), "results": responses}


@router.post("/correlate")
async def correlate_iocs(
    ioc_values: list[str],
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Find correlations between multiple IOCs."""
    if len(ioc_values) > 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 50 IOCs for correlation analysis",
        )

    indicators = []
    for value in ioc_values:
        try:
            response = await enrichment_engine.enrich_ioc(EnrichmentRequest(ioc_value=value))
            if response.ioc:
                indicators.append(response.ioc)
        except Exception as exc:
            logger.warning("Failed to enrich IOC for correlation: {}", exc)

    if not indicators:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid IOCs to correlate",
        )

    correlations = CorrelationEngine.correlate_indicators(indicators)
    infrastructure = CorrelationEngine.find_common_infrastructure(indicators)
    threat_graph = CorrelationEngine.build_threat_graph(indicators)
    recommendations = CorrelationEngine.get_investigation_recommendations(indicators)

    logger.info(
        "IOCs correlated: user={}, count={}, infrastructure_items={}",
        user["email"],
        len(indicators),
        len(infrastructure),
    )

    return {
        "indicators_analyzed": len(indicators),
        "correlations": correlations,
        "infrastructure": infrastructure,
        "threat_graph": threat_graph,
        "recommendations": recommendations,
    }


@router.get("/threat-graph/{ioc_value}")
async def get_threat_graph(
    ioc_value: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Generate threat graph for an IOC showing relationships."""
    try:
        response = await enrichment_engine.enrich_ioc(EnrichmentRequest(ioc_value=ioc_value))

        if not response.ioc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unable to enrich IOC",
            )

        threat_graph = CorrelationEngine.build_threat_graph([response.ioc])

        return {
            "ioc": ioc_value,
            "threat_level": response.ioc.threat_level.value,
            "risk_score": response.ioc.risk_score,
            "graph": threat_graph,
        }

    except Exception as exc:
        logger.error("Threat graph generation failed: {}", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Threat graph generation failed",
        ) from exc


# ============================================================================
# Unified Intelligence & Export Endpoints (Phase 5)
# ============================================================================

@router.post("/unified-enrich", response_model=UnifiedIntelligenceReport)
async def unified_enrich_ioc(
    ioc_value: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Unified enrichment combining VirusTotal, Shodan, and IPinfo data.
    Returns correlated findings and scores from all sources.
    """
    try:
        # Perform unified enrichment
        report = await unified_service.enrich(ioc_value)

        # Store minimal audit trail without exposing provider names
        await db.unified_enrichments.insert_one({
            "user_id": str(user["_id"]),
            "ioc_value": report.ioc_value,
            "ioc_type": report.ioc_type,
            "threat_score": report.threat_score,
            "risk_level": report.risk_level.value,
            "confidence_score": report.confidence_score,
            "findings_count": len(report.findings),
            "sources_queried_count": len(report.sources_queried),
            "sources_failed_count": len(report.sources_failed),
            "investigation_timestamp": report.investigation_timestamp,
            "created_at": datetime.now(timezone.utc),
        })

        logger.info(
            "Unified enrichment completed",
            user=user["email"],
            ioc=ioc_value,
            threat_score=report.threat_score,
            sources_count=len(report.sources_queried)
        )

        # Remove provider names from the returned report to avoid leaking external source identities
        report.sources_queried = []
        report.sources_failed = []

        return report

    except Exception as exc:
        logger.error("Unified enrichment failed: {}", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unified enrichment failed",
        ) from exc


@router.post("/export/pdf")
async def export_pdf(
    report: UnifiedIntelligenceReport,
    analyst_notes: str = "",
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Export unified intelligence report as PDF.
    Includes all source data, findings, and analyst notes.
    """
    try:
        # Generate timestamped filename
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        safe_ioc = report.ioc_value.replace("/", "_").replace(":", "_")
        filename = f"report_{safe_ioc}_{timestamp}.pdf"

        # Generate PDF
        # Sanitize report to avoid exposing provider identities in exported documents
        report.sources_queried = []
        report.sources_failed = []
        report.virustotal = None
        report.shodan = None
        report.ipinfo = None

        pdf_buffer = pdf_generator.generate_report(
            report,
            analyst_notes=analyst_notes,
            filename=filename
        )

        # Log export
        await db.exports.insert_one({
            "user_id": str(user["_id"]),
            "ioc_value": report.ioc_value,
            "format": "pdf",
            "filename": filename,
            "threat_score": report.threat_score,
            "created_at": datetime.now(timezone.utc),
        })

        logger.info(
            "PDF export generated",
            user=user["email"],
            ioc=report.ioc_value,
            filename=filename
        )

        return StreamingResponse(
            iter([pdf_buffer.getvalue()]),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as exc:
        logger.error("PDF export failed: {}", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="PDF export failed",
        ) from exc


@router.post("/export/csv")
async def export_csv(
    report: UnifiedIntelligenceReport,
    analyst_notes: str = "",
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Export unified intelligence report as CSV.
    Includes all source data in tabular format.
    """
    try:
        # Generate timestamped filename
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        safe_ioc = report.ioc_value.replace("/", "_").replace(":", "_")
        filename = f"report_{safe_ioc}_{timestamp}.csv"

        # Generate CSV
        # Sanitize report to avoid exposing provider identities in exported documents
        report.sources_queried = []
        report.sources_failed = []
        report.virustotal = None
        report.shodan = None
        report.ipinfo = None

        csv_buffer = csv_generator.generate_report(
            report,
            analyst_notes=analyst_notes,
            filename=filename
        )

        # Log export
        await db.exports.insert_one({
            "user_id": str(user["_id"]),
            "ioc_value": report.ioc_value,
            "format": "csv",
            "filename": filename,
            "threat_score": report.threat_score,
            "created_at": datetime.now(timezone.utc),
        })

        logger.info(
            "CSV export generated",
            user=user["email"],
            ioc=report.ioc_value,
            filename=filename
        )

        return StreamingResponse(
            iter([csv_buffer.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as exc:
        logger.error("CSV export failed: {}", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="CSV export failed",
        ) from exc


@router.post("/export/json")
async def export_json(
    report: UnifiedIntelligenceReport,
    analyst_notes: str = "",
    include_raw_responses: bool = True,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Export unified intelligence report as JSON.
    Includes all source data in machine-readable format for automation and integration.
    """
    try:
        # Generate timestamped filename
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        safe_ioc = report.ioc_value.replace("/", "_").replace(":", "_")
        filename = f"report_{safe_ioc}_{timestamp}.json"

        # Generate JSON
        json_buffer = json_generator.generate_report(
            report,
            analyst_notes=analyst_notes,
            include_raw_responses=include_raw_responses,
            filename=filename
        )

        # Log export
        await db.exports.insert_one({
            "user_id": str(user["_id"]),
            "ioc_value": report.ioc_value,
            "format": "json",
            "filename": filename,
            "threat_score": report.threat_score,
            "created_at": datetime.now(timezone.utc),
        })

        logger.info(
            "JSON export generated",
            user=user["email"],
            ioc=report.ioc_value,
            filename=filename
        )

        return StreamingResponse(
            iter([json_buffer.getvalue()]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as exc:
        logger.error("JSON export failed: {}", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JSON export failed",
        ) from exc


# ============================================================================
# Raw Intelligence Response Viewer Endpoints
# ============================================================================

@router.get("/raw-response/virustotal/{ioc_value}")
async def get_virustotal_raw_response(
    ioc_value: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Retrieve raw VirusTotal API response for an IOC.
    Provides direct access to unmodified provider data for transparency.
    """
    try:
        # Check if we have cached enrichment
        enrichment = await db.unified_enrichments.find_one({
            "ioc_value": ioc_value,
            "user_id": str(user["_id"])
        })

        if not enrichment:
            # Perform fresh enrichment
            report = await unified_service.enrich(ioc_value)
        else:
            # Return cached raw response
            if enrichment.get("virustotal", {}).get("raw_response"):
                return {
                    "ioc": ioc_value,
                    "source": "VirusTotal",
                    "raw_response": enrichment["virustotal"]["raw_response"],
                    "cached": True
                }
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="No VirusTotal data available for this IOC"
                )

        logger.info(
            "Raw VirusTotal response retrieved",
            user=user["email"],
            ioc=ioc_value
        )

        return {
            "ioc": ioc_value,
            "source": "VirusTotal",
            "raw_response": report.virustotal.raw_response if report.virustotal else {},
            "cached": False
        }

    except Exception as exc:
        logger.error("Failed to retrieve VirusTotal raw response: {}", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve VirusTotal raw response",
        ) from exc


@router.get("/raw-response/shodan/{ioc_value}")
async def get_shodan_raw_response(
    ioc_value: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Retrieve raw Shodan API response for an IOC.
    Provides direct access to unmodified provider data for transparency.
    """
    try:
        # Perform enrichment if needed
        report = await unified_service.enrich(ioc_value)

        if not report.shodan or not report.shodan.raw_response:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No Shodan data available for this IOC"
            )

        logger.info(
            "Raw Shodan response retrieved",
            user=user["email"],
            ioc=ioc_value
        )

        return {
            "ioc": ioc_value,
            "source": "Shodan",
            "raw_response": report.shodan.raw_response
        }

    except Exception as exc:
        logger.error("Failed to retrieve Shodan raw response: {}", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve Shodan raw response",
        ) from exc


@router.get("/raw-response/ipinfo/{ioc_value}")
async def get_ipinfo_raw_response(
    ioc_value: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Retrieve raw IPinfo API response for an IOC.
    Provides direct access to unmodified provider data for transparency.
    """
    try:
        # Perform enrichment if needed
        report = await unified_service.enrich(ioc_value)

        if not report.ipinfo or not report.ipinfo.raw_response:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No IPinfo data available for this IOC"
            )

        logger.info(
            "Raw IPinfo response retrieved",
            user=user["email"],
            ioc=ioc_value
        )

        return {
            "ioc": ioc_value,
            "source": "IPinfo",
            "raw_response": report.ipinfo.raw_response
        }

    except Exception as exc:
        logger.error("Failed to retrieve IPinfo raw response: {}", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve IPinfo raw response",
        ) from exc


# ============================================================================
# Explainable Findings Endpoints
# ============================================================================

@router.get("/findings/explainable/{ioc_value}")
async def get_explainable_findings(
    ioc_value: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Get explainable findings with reasoning for an IOC.
    Provides transparent threat analysis with detailed explanations.
    """
    try:
        # Perform enrichment
        report = await unified_service.enrich(ioc_value)

        # Generate explainable findings
        findings = findings_generator.generate_findings(report)
        reasoning = findings_generator.generate_reasoning_explanation(report)

        logger.info(
            "Explainable findings generated",
            user=user["email"],
            ioc=ioc_value,
            findings_count=len(findings)
        )

        return {
            "ioc": ioc_value,
            "findings": [
                {
                    "type": f.finding_type.value,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "source": f.source,
                    "evidence": f.evidence,
                    "confidence": f.confidence,
                }
                for f in findings
            ],
            "reasoning": reasoning,
            "summary": findings_generator._extract_key_factors(report)
        }

    except Exception as exc:
        logger.error("Failed to generate explainable findings: {}", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate explainable findings",
        ) from exc
