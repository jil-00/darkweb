from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.core.config import get_settings


class Database:
    client: AsyncIOMotorClient | None = None
    db: AsyncIOMotorDatabase | None = None


database = Database()


async def connect_to_mongo() -> None:
    settings = get_settings()
    database.client = AsyncIOMotorClient(settings.mongodb_url)
    database.db = database.client[settings.mongodb_db_name]


async def close_mongo_connection() -> None:
    if database.client is not None:
        database.client.close()
        database.client = None
        database.db = None


def get_db() -> AsyncIOMotorDatabase:
    if database.db is None:
        raise RuntimeError("Database not initialized")
    return database.db