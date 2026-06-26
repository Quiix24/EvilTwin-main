from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_settings
from database import get_db
from schemas import LogIngestRequest, LogIngestResponse
from services.ingest import ingest_event

router = APIRouter(prefix="", tags=["ingest"])
settings = get_settings()

def _check_ingest_auth(x_ingest_key: str = Header("", alias="X-Ingest-Key")) -> None:
    if x_ingest_key != settings.SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid ingest key")

@router.post("/log", response_model=LogIngestResponse, dependencies=[Depends(_check_ingest_auth)])
async def ingest_log(payload: LogIngestRequest, db: AsyncSession = Depends(get_db)) -> LogIngestResponse:
    return await ingest_event(payload, db)
