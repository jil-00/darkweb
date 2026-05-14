from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import get_settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.schemas import SearchRequest, SearchResponse
from app.services.alerting import maybe_create_alert
from app.services.intelligence import run_intelligence

router = APIRouter(tags=["scan"])


@router.post("/scan", response_model=SearchResponse)
async def scan_query(
    payload: SearchRequest,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    result = await run_intelligence(
        query=payload.query,
        query_type=payload.query_type,
        use_regex=payload.use_regex,
        fuzzy=payload.fuzzy,
    )
    created_at = datetime.now(timezone.utc)

    await db.findings.insert_one(
        {
            "user_id": str(user["_id"]),
            "query": result["query"],
            "query_type": result["query_type"],
            "risk_score": result["risk_score"],
            "findings": result["findings"],
            "correlation": result["correlation"],
            "created_at": created_at,
            "origin": "scan_api",
        }
    )
    await db.queries.insert_one(
        {
            "user_id": str(user["_id"]),
            "query": result["query"],
            "query_type": result["query_type"],
            "created_at": created_at,
        }
    )

    settings = get_settings()
    await maybe_create_alert(
        db=db,
        user_id=str(user["_id"]),
        query=result["query"],
        risk_score=result["risk_score"],
        threshold=settings.alert_risk_threshold,
    )

    return SearchResponse(
        query=result["query"],
        query_type=result["query_type"],
        total_findings=len(result["findings"]),
        risk_score=result["risk_score"],
        findings=result["findings"],
        created_at=created_at,
    )


@router.get("/results/{query}")
async def get_results(
    query: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    normalized_query = query.strip().lower()
    existing = await db.findings.find_one(
        {"user_id": str(user["_id"]), "query": normalized_query},
        sort=[("created_at", -1)],
    )
    if not existing:
        raise HTTPException(status_code=404, detail="No cached result for query")
    return {
        "query": existing["query"],
        "query_type": existing["query_type"],
        "total_findings": len(existing.get("findings", [])),
        "risk_score": existing["risk_score"],
        "findings": existing["findings"],
        "correlation": existing.get("correlation", {}),
        "created_at": existing["created_at"],
        "origin": existing.get("origin", "scan_api"),
    }
