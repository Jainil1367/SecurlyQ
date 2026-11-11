"""Alert routes: list, detail, status changes, investigation notes, dashboard summary."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.deps import analyst_or_admin, any_user
from app.core.config import get_settings
from app.core.rate_limit import SlidingWindowRateLimiter
from app.db.session import get_db
from app.llm.explainer import LLMExplainer, get_explainer
from app.models import Alert, AlertEvidence, Event, Investigation, User
from app.schemas.alert import (
    AlertDetail,
    AlertOut,
    AlertPage,
    AlertStatus,
    AlertSummary,
    AlertUpdate,
    EvidenceOut,
    NoteIn,
    NoteOut,
    Severity,
)
from app.schemas.event import EventOut
from app.schemas.explanation import ExplanationOut

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

# Each explanation can cost money (Bedrock bills per token), so cap how often one user can trigger it.
explain_limiter = SlidingWindowRateLimiter(max_events=get_settings().llm_requests_per_hour, window_seconds=3600)


def _with_counts(db: Session, alerts: list[Alert]) -> list[AlertOut]:
    """Attach evidence_count with one grouped query (avoids the N+1 query trap)."""
    counts: dict[int, int] = {}
    if alerts:
        rows = db.execute(
            select(AlertEvidence.alert_id, func.count())
            .where(AlertEvidence.alert_id.in_([a.id for a in alerts]))
            .group_by(AlertEvidence.alert_id)
        )
        counts = dict(rows.all())
    out = []
    for a in alerts:
        item = AlertOut.model_validate(a)
        item.evidence_count = counts.get(a.id, 0)
        out.append(item)
    return out


def _evidence(db: Session, alert_id: int) -> list[tuple[str, Event]]:
    """(reason, event) pairs for an alert, oldest first."""
    rows = db.execute(
        select(AlertEvidence.reason, Event)
        .join(Event, Event.id == AlertEvidence.event_id)
        .where(AlertEvidence.alert_id == alert_id)
        .order_by(Event.timestamp, Event.id)
    ).all()
    return [(reason, event) for reason, event in rows]


def _get_or_404(db: Session, alert_id: int) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return alert


@router.get("", response_model=AlertPage)
def list_alerts(
    db: Session = Depends(get_db),
    _: User = Depends(any_user),
    status_: AlertStatus | None = Query(None, alias="status"),
    severity: Severity | None = None,
    rule_id: str | None = None,
    source_ip: str | None = None,
    min_risk: float | None = Query(None, ge=0, le=100),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> AlertPage:
    """Highest-risk alerts first."""
    query = select(Alert)
    if status_:
        query = query.where(Alert.status == status_)
    if severity:
        query = query.where(Alert.severity == severity)
    if rule_id:
        query = query.where(Alert.rule_id == rule_id)
    if source_ip:
        query = query.where(Alert.source_ip == source_ip)
    if min_risk is not None:
        query = query.where(Alert.risk_score >= min_risk)

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = list(
        db.scalars(
            query.order_by(desc(Alert.risk_score), desc(Alert.created_at), desc(Alert.id))
            .limit(limit)
            .offset(offset)
        )
    )
    return AlertPage(items=_with_counts(db, rows), total=total, limit=limit, offset=offset)


# NOTE: declared before "/{alert_id}" so "summary" isn't parsed as an id.
@router.get("/summary", response_model=AlertSummary)
def alert_summary(db: Session = Depends(get_db), _: User = Depends(any_user)) -> AlertSummary:
    """Aggregates for the dashboard, computed in SQL with GROUP BY."""
    by_status = dict(db.execute(select(Alert.status, func.count()).group_by(Alert.status)).all())
    open_by_severity = dict(
        db.execute(
            select(Alert.severity, func.count()).where(Alert.status == "open").group_by(Alert.severity)
        ).all()
    )
    count_col = func.count().label("alerts")
    top_ips = [
        {"source_ip": ip, "alerts": n}
        for ip, n in db.execute(
            select(Alert.source_ip, count_col)
            .where(Alert.source_ip.is_not(None))
            .group_by(Alert.source_ip)
            .order_by(desc(count_col))
            .limit(5)
        ).all()
    ]

    acked = db.execute(
        select(Alert.created_at, Alert.acknowledged_at)
        .where(Alert.acknowledged_at.is_not(None))
        .order_by(desc(Alert.acknowledged_at))
        .limit(1000)
    ).all()
    mtta = None
    if acked:
        deltas = [(a - c).total_seconds() for c, a in acked]
        mtta = round(sum(deltas) / len(deltas), 1)

    return AlertSummary(
        total_alerts=sum(by_status.values()),
        by_status=by_status,
        open_by_severity=open_by_severity,
        top_source_ips=top_ips,
        mean_time_to_acknowledge_seconds=mtta,
    )


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: int, db: Session = Depends(get_db), _: User = Depends(any_user)) -> AlertDetail:
    alert = _get_or_404(db, alert_id)
    evidence_rows = _evidence(db, alert_id)
    note_rows = db.execute(
        select(Investigation, User.email)
        .outerjoin(User, User.id == Investigation.assigned_to)
        .where(Investigation.alert_id == alert_id)
        .order_by(Investigation.id)
    ).all()

    base = _with_counts(db, [alert])[0]
    return AlertDetail(
        **base.model_dump(),
        explanation=alert.explanation,
        evidence=[
            EvidenceOut(reason=reason, event=EventOut.model_validate(event))
            for reason, event in evidence_rows
        ],
        investigation_notes=[
            NoteOut(
                id=inv.id,
                author_id=inv.assigned_to,
                author_email=email,
                notes=inv.notes,
                updated_at=inv.updated_at,
            )
            for inv, email in note_rows
        ],
    )


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(
    alert_id: int,
    body: AlertUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(analyst_or_admin),
) -> AlertOut:
    """Change an alert's status (acknowledge, resolve, mark false positive, reopen)."""
    alert = _get_or_404(db, alert_id)
    alert.status = body.status
    if body.status == "open":
        alert.acknowledged_at = None
    elif alert.acknowledged_at is None:
        alert.acknowledged_at = datetime.now(UTC)  # first human response; feeds the MTTA metric
    db.commit()
    return _with_counts(db, [alert])[0]


@router.post("/{alert_id}/notes", response_model=NoteOut, status_code=status.HTTP_201_CREATED)
def add_note(
    alert_id: int,
    body: NoteIn,
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
) -> NoteOut:
    """Append an investigation note. Each row is one entry in the alert's review history."""
    _get_or_404(db, alert_id)
    note = Investigation(alert_id=alert_id, assigned_to=user.id, notes=body.notes)
    db.add(note)
    db.commit()
    return NoteOut(
        id=note.id,
        author_id=user.id,
        author_email=user.email,
        notes=note.notes,
        updated_at=note.updated_at,
    )


@router.post("/{alert_id}/explain", response_model=ExplanationOut)
def explain_alert(
    alert_id: int,
    refresh: bool = False,
    db: Session = Depends(get_db),
    user: User = Depends(analyst_or_admin),
    explainer: LLMExplainer = Depends(get_explainer),
) -> ExplanationOut | dict:
    """Plain-English explanation of an alert (Amazon Bedrock, or a template fallback).

    Generated on demand and stored with the alert. Pass `?refresh=true` to regenerate.
    The text is advisory: it never changes status and never triggers any action.
    """
    alert = _get_or_404(db, alert_id)
    if alert.explanation and not refresh:
        return alert.explanation  # already generated: free, instant

    key = f"user:{user.id}"
    if explain_limiter.is_blocked(key):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Explanation limit reached. Try again later.",
            headers={"Retry-After": str(explain_limiter.retry_after(key))},
        )
    explanation = explainer.explain(alert, _evidence(db, alert_id))
    if explainer.generator is not None:
        explain_limiter.record(key)  # only real model calls count against the budget

    alert.explanation = explanation.model_dump(mode="json")
    db.commit()
    return explanation
