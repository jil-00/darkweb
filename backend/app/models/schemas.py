from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: Literal["user", "admin"] = "user"


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class SearchRequest(BaseModel):
    query: str = Field(min_length=3, max_length=256)
    query_type: Literal["email", "domain", "username"]
    use_regex: bool = False
    fuzzy: bool = True


class Finding(BaseModel):
    source: str
    source_type: str
    observed_value: str
    matched_entity: str
    category: Literal["credential", "pii", "financial", "internal"]
    sensitivity: float = Field(ge=0.1, le=2.0)
    source_weight: float = Field(ge=0.1, le=2.0)
    occurrences: int = Field(ge=1)
    first_seen: datetime
    last_seen: datetime
    raw: dict


class SearchResponse(BaseModel):
    query: str
    query_type: str
    total_findings: int
    risk_score: float
    findings: list[Finding]
    created_at: datetime


class DashboardStats(BaseModel):
    total_queries: int
    total_findings: int
    active_alerts: int
    average_risk_score: float


class RiskTrendPoint(BaseModel):
    date: str
    avg_risk: float


class SourceBreakdown(BaseModel):
    source: str
    count: int


class DashboardResponse(BaseModel):
    stats: DashboardStats
    trends: list[RiskTrendPoint]
    top_sources: list[SourceBreakdown]


class AlertItem(BaseModel):
    id: str
    query: str
    risk_score: float
    reason: str
    created_at: datetime
    status: Literal["open", "acknowledged"]


class WatchCreate(BaseModel):
    target: str = Field(min_length=3, max_length=256)
    query_type: Literal["email", "domain", "username"]
    interval_minutes: int = Field(default=30, ge=5, le=1440)


class WatchItem(BaseModel):
    id: str
    target: str
    query_type: str
    interval_minutes: int
    last_scanned_at: datetime | None = None
    created_at: datetime
