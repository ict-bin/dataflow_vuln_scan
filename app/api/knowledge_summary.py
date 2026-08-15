from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import ensure_project_access, get_current_user
from app.db import get_db
from app.db.models import AppDvsKnowledgeSummaryScanState, AppDvsKnowledgeSummaryTask
from app.service.knowledge_summary import enqueue_knowledge_summary_task

from . import router

knowledge_router = APIRouter(prefix="/knowledge-summaries", tags=["knowledge-summaries"])


def _row(row: AppDvsKnowledgeSummaryTask, detail: bool = False) -> dict:
    knowledge = row.result_json if isinstance(row.result_json, dict) else {}
    payload = {
        "id": row.id,
        "summary_task_id": row.summary_task_id,
        "project_id": row.project_id,
        "case_id": row.case_id,
        "dvs_task_id": row.dvs_task_id,
        "finding_id": row.finding_id,
        "decision": row.decision,
        "status": row.status,
        "error_message": row.error_message,
        "attempt_count": row.attempt_count,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "started_at": row.started_at,
        "finished_at": row.finished_at,
        "knowledge_summary": str(knowledge.get("label_reason") or knowledge.get("label") or "")[:500] or None,
    }
    if detail:
        payload.update({
            "knowledge": row.result_json,
            "source_case": {"case_id": row.case_id, "decision": row.decision},
            "finding_report": {
                "task_id": row.dvs_task_id,
                "finding_id": row.finding_id,
            },
        })
    return payload


@knowledge_router.get("")
def list_knowledge_summaries(
    project_id: str = Query(...),
    status: str | None = Query(None),
    decision: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    user_and_token: tuple[dict, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ensure_project_access(project_id, user_and_token[1])
    query = select(AppDvsKnowledgeSummaryTask).where(AppDvsKnowledgeSummaryTask.project_id == project_id)
    if status:
        query = query.where(AppDvsKnowledgeSummaryTask.status == status)
    if decision:
        query = query.where(AppDvsKnowledgeSummaryTask.decision == decision)
    total = int(db.execute(select(func.count()).select_from(query.subquery())).scalar() or 0)
    rows = db.execute(query.order_by(AppDvsKnowledgeSummaryTask.updated_at.desc()).offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return {"items": [_row(item) for item in rows], "total": total, "page": page, "page_size": page_size}


@knowledge_router.get("/scan-status")
def get_knowledge_summary_scan_status(
    project_id: str = Query(...),
    user_and_token: tuple[dict, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ensure_project_access(project_id, user_and_token[1])
    state = db.execute(select(AppDvsKnowledgeSummaryScanState).order_by(AppDvsKnowledgeSummaryScanState.updated_at.desc())).scalars().first()
    counts = dict(db.execute(
        select(AppDvsKnowledgeSummaryTask.status, func.count(AppDvsKnowledgeSummaryTask.id))
        .where(AppDvsKnowledgeSummaryTask.project_id == project_id)
        .group_by(AppDvsKnowledgeSummaryTask.status)
    ).all())
    return {
        "project_id": project_id,
        "last_successful_scan_at": state.last_successful_scan_at if state else None,
        "watermark_updated_at": state.watermark_updated_at if state else None,
        "last_full_scan_at": state.last_full_scan_at if state else None,
        "last_error": state.last_error if state else None,
        "last_scan_case_count": state.last_scan_case_count if state else 0,
        "last_created_count": state.last_created_count if state else 0,
        "last_skipped_count": state.last_skipped_count if state else 0,
        "last_dispatched_count": state.last_dispatched_count if state else 0,
        "task_status_counts": counts,
    }


@knowledge_router.get("/{summary_task_id}")
def get_knowledge_summary(
    summary_task_id: str,
    project_id: str = Query(...),
    user_and_token: tuple[dict, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ensure_project_access(project_id, user_and_token[1])
    row = db.execute(select(AppDvsKnowledgeSummaryTask).where(
        AppDvsKnowledgeSummaryTask.summary_task_id == summary_task_id,
        AppDvsKnowledgeSummaryTask.project_id == project_id,
    )).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="knowledge summary not found")
    return _row(row, detail=True)


@knowledge_router.post("/{summary_task_id}/retry")
def retry_knowledge_summary(
    summary_task_id: str,
    project_id: str = Query(...),
    user_and_token: tuple[dict, str] = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ensure_project_access(project_id, user_and_token[1])
    row = db.execute(select(AppDvsKnowledgeSummaryTask).where(
        AppDvsKnowledgeSummaryTask.summary_task_id == summary_task_id,
        AppDvsKnowledgeSummaryTask.project_id == project_id,
    )).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="knowledge summary not found")
    if row.status != "failed":
        raise HTTPException(status_code=409, detail="only failed summaries can be retried")
    row.status = "queued"
    row.error_message = None
    row.finished_at = None
    row.lease_until = None
    row.celery_task_id = None
    row.dispatch_requested_at = None
    row.last_dispatch_error = None
    db.commit()
    if not enqueue_knowledge_summary_task(summary_task_id):
        raise HTTPException(status_code=503, detail="knowledge summary dispatch unavailable")
    return _row(row)


router.include_router(knowledge_router)
