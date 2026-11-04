from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import analyst_or_admin
from app.db.session import get_db
from app.models import User
from app.schemas.alert import AnalysisRequest, AnalysisResultOut
from app.services.analysis import AnalysisService, AnalysisTooLarge

router = APIRouter(prefix="/api/v1/analysis", tags=["analysis"])


@router.post("/run", response_model=AnalysisResultOut)
def run_analysis(
    body: AnalysisRequest | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(analyst_or_admin),
) -> AnalysisResultOut:
    """Run detection rules over a time window (default: the last 24 hours)."""
    body = body or AnalysisRequest()
    if body.since and body.until and body.since >= body.until:
        raise HTTPException(422, "`since` must be before `until`")
    if body.until and body.until > datetime.now(UTC):
        body.until = datetime.now(UTC)
    try:
        result = AnalysisService(db).run(since=body.since, until=body.until)
    except AnalysisTooLarge as exc:
        raise HTTPException(413, str(exc)) from exc
    return AnalysisResultOut(**vars(result))
