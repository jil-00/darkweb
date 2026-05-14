from datetime import datetime, timezone

from app.core.config import get_settings
from app.services.alerting import maybe_create_alert
from app.services.intelligence import run_intelligence


async def run_watch_scan(db) -> None:
    settings = get_settings()
    watches = db.watches.find({})
    async for watch in watches:
        result = await run_intelligence(
            query=watch["target"],
            query_type=watch["query_type"],
            use_regex=False,
            fuzzy=True,
        )

        await db.findings.insert_one(
            {
                "user_id": watch["user_id"],
                "query": result["query"],
                "query_type": result["query_type"],
                "risk_score": result["risk_score"],
                "findings": result["findings"],
                "correlation": result["correlation"],
                "created_at": datetime.now(timezone.utc),
                "origin": "watch_scan",
            }
        )

        await maybe_create_alert(
            db=db,
            user_id=watch["user_id"],
            query=watch["target"],
            risk_score=result["risk_score"],
            threshold=settings.alert_risk_threshold,
        )

        await db.watches.update_one(
            {"_id": watch["_id"]},
            {"$set": {"last_scanned_at": datetime.now(timezone.utc)}},
        )