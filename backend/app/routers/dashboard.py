from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.schemas import DashboardResponse

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/overview", response_model=DashboardResponse)
async def dashboard_overview(
    db: AsyncIOMotorDatabase = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    user_id = str(user["_id"])
    total_queries = await db.queries.count_documents({"user_id": user_id})
    total_findings = await db.findings.count_documents({"user_id": user_id})
    active_alerts = await db.alerts.count_documents({"user_id": user_id, "status": "open"})

    pipeline_avg = [
        {"$match": {"user_id": user_id}},
        {"$group": {"_id": None, "avg": {"$avg": "$risk_score"}}},
    ]
    avg_result = await db.findings.aggregate(pipeline_avg).to_list(length=1)
    average_risk = round(avg_result[0]["avg"], 2) if avg_result else 0.0

    trends = []
    now = datetime.now(timezone.utc)
    for days_ago in range(6, -1, -1):
        day_start = (now - timedelta(days=days_ago)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        day_end = day_start + timedelta(days=1)
        daily = await db.findings.aggregate(
            [
                {
                    "$match": {
                        "user_id": user_id,
                        "created_at": {"$gte": day_start, "$lt": day_end},
                    }
                },
                {"$group": {"_id": None, "avg": {"$avg": "$risk_score"}}},
            ]
        ).to_list(length=1)
        trends.append(
            {
                "date": day_start.strftime("%Y-%m-%d"),
                "avg_risk": round(daily[0]["avg"], 2) if daily else 0.0,
            }
        )

    source_pipeline = [
        {"$match": {"user_id": user_id}},
        {"$unwind": "$findings"},
        {"$group": {"_id": "$findings.source", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5},
    ]
    source_rows = await db.findings.aggregate(source_pipeline).to_list(length=5)
    top_sources = [{"source": row["_id"], "count": row["count"]} for row in source_rows]

    return {
        "stats": {
            "total_queries": total_queries,
            "total_findings": total_findings,
            "active_alerts": active_alerts,
            "average_risk_score": average_risk,
        },
        "trends": trends,
        "top_sources": top_sources,
    }