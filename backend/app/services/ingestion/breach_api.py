from datetime import datetime, timedelta, timezone
from random import randint, random

from app.services.ingestion.base_scraper import BaseScraper


class BreachAPIConnector(BaseScraper):
    source_name = "breach_db"
    source_type = "api"

    async def collect(self, query: str, query_type: str) -> list[dict]:
        count = randint(1, 3)
        first_seen = datetime.now(timezone.utc) - timedelta(days=randint(5, 360))
        return [
            {
                "source": self.source_name,
                "source_type": self.source_type,
                "query": query,
                "data_type": query_type,
                "payload": {
                    "match": query,
                    "occurrences": randint(1, 5),
                    "contains_password": random() > 0.5,
                    "confidence": round(0.6 + random() * 0.35, 2),
                },
                "first_seen": first_seen,
                "last_seen": first_seen + timedelta(days=randint(0, 120)),
            }
            for _ in range(count)
        ]
