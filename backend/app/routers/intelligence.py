from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import get_settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.schemas import SearchRequest, SearchResponse
from app.services.alerting import maybe_create_alert
from app.services.intelligence import run_intelligence

router = APIRouter(prefix="/intel", tags=["intelligence"])


@router.post("/search", response_model=SearchResponse)
async def search_intelligence(
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
    await db.queries.insert_one(
        {
            "user_id": str(user["_id"]),
            "query": result["query"],
            "query_type": result["query_type"],
            "created_at": created_at,
        }
    )
    await db.findings.insert_one(
        {
            "user_id": str(user["_id"]),
            "query": result["query"],
            "query_type": result["query_type"],
            "risk_score": result["risk_score"],
            "findings": result["findings"],
            "correlation": result["correlation"],
            "created_at": created_at,
            "origin": "manual_search",
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


@router.get("/history")
async def query_history(
    limit: int = 20,
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    cursor = (
        db.findings.find({"user_id": str(user["_id"])})
        .sort("created_at", -1)
        .limit(max(1, min(100, limit)))
    )

    records = []
    async for item in cursor:
        records.append(
            {
                "id": str(item.get("_id", ObjectId())),
                "query": item["query"],
                "query_type": item["query_type"],
                "risk_score": item["risk_score"],
                "created_at": item["created_at"],
                "origin": item.get("origin", "manual_search"),
            }
        )
    return records