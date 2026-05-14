from datetime import datetime, timedelta, timezone
from random import randint, random

from app.services.ingestion.base_scraper import BaseScraper


class PasteMonitor(BaseScraper):
    source_name = "paste_feed"
    source_type = "paste"

    async def collect(self, query: str, query_type: str) -> list[dict]:
        count = randint(1, 4)
        base_time = datetime.now(timezone.utc) - timedelta(days=randint(1, 90))
        return [
            {
                "source": self.source_name,
                "source_type": self.source_type,
                "query": query,
                "data_type": query_type,
                "payload": {
                    "match": query,
                    "occurrences": randint(1, 3),
                    "contains_password": random() > 0.7,
                    "confidence": round(0.5 + random() * 0.35, 2),
                },
                "first_seen": base_time,
                "last_seen": base_time + timedelta(days=randint(0, 30)),
            }
            for _ in range(count)
        ]
