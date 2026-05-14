from motor.motor_asyncio import AsyncIOMotorDatabase

from app.services.risk import score_result


async def rescore_persisted_risk(db: AsyncIOMotorDatabase) -> tuple[int, int]:
    findings_updated = 0
    alerts_updated = 0

    cursor = db.findings.find({}, {"_id": 1, "findings": 1, "risk_score": 1, "query": 1, "query_type": 1})
    async for doc in cursor:
        new_score = score_result(
            doc.get("findings", []),
            domain=doc.get("query"),
            query_type=doc.get("query_type"),
        )
        old_score = float(doc.get("risk_score", 0.0))
        if round(old_score, 2) != new_score:
            await db.findings.update_one(
                {"_id": doc["_id"]},
                {"$set": {"risk_score": new_score}},
            )
            findings_updated += 1

    alert_cursor = db.alerts.find({}, {"_id": 1, "user_id": 1, "query": 1, "risk_score": 1})
    async for alert in alert_cursor:
        latest_finding = await db.findings.find_one(
            {
                "user_id": alert.get("user_id"),
                "query": alert.get("query", "").strip().lower(),
            },
            sort=[("created_at", -1)],
            projection={"risk_score": 1, "findings": 1, "query": 1, "query_type": 1},
        )
        if not latest_finding:
            continue

        new_alert_score = score_result(
            latest_finding.get("findings", []),
            domain=latest_finding.get("query"),
            query_type=latest_finding.get("query_type"),
        )
        old_alert_score = float(alert.get("risk_score", 0.0))
        if round(old_alert_score, 2) != round(new_alert_score, 2):
            await db.alerts.update_one(
                {"_id": alert["_id"]},
                {"$set": {"risk_score": round(new_alert_score, 2)}},
            )
            alerts_updated += 1

    return findings_updated, alerts_updated
