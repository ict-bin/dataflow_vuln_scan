"""failure_debug.py — 失败调试报告 API（debugger 角色）。

GET  /failure-debug-reports            列表（project_id 过滤、分页）
GET  /failure-debug-reports/{id}        详情
GET  /failure-debug-reports/{id}/download  下载 Markdown 报告
DELETE /failure-debug-reports/{id}     删除报告（标记已处理）
GET  /failure-debug/config             获取调试模型配置 + 可用模型列表
PUT  /failure-debug/config             保存调试模型配置
POST /internal/failure-debug           worker 下发：任务失败后通知 debugger 调试
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import OUTPUT_DIR
from app.db import get_db
from app.db.models import AppDvsFailureDebug, AppDvsTask
from app.service.config_service import get_config_service
from app.service.failure_debug import FailureDebugService

from . import router


@router.get("/failure-debug/config")
def get_failure_debug_config(db: Session = Depends(get_db)):
    """获取 debugger 调试模型配置 + 可用模型列表。"""
    cfg = get_config_service().get_failure_debug_config(db)
    available = FailureDebugService.list_available_models()
    return {"model": cfg.get("model") or "", "available_models": available, "updated_at": cfg.get("updated_at")}


@router.put("/failure-debug/config")
def save_failure_debug_config(payload: dict, db: Session = Depends(get_db)):
    """保存 debugger 调试模型配置。"""
    model = str((payload or {}).get("model") or "").strip()
    result = get_config_service().save_failure_debug_config(db, model)
    return {"model": result.get("model") or "", "saved": True}


@router.post("/internal/failure-debug", include_in_schema=False)
def submit_failure_debug(payload: dict, db: Session = Depends(get_db)):
    """worker 下发：任务失败后通知 debugger 调试。创建 pending 行 + 唤醒 debugger worker。"""
    task_id = str((payload or {}).get("task_id") or "").strip()
    if not task_id:
        raise HTTPException(status_code=400, detail="task_id required")
    # 幂等创建 pending 行（持久化下发意图，debugger 崩溃后启动扫描可恢复）
    row = db.query(AppDvsFailureDebug).filter(AppDvsFailureDebug.task_id == task_id).first()
    created = False
    if row is None:
        task = db.query(AppDvsTask).filter(AppDvsTask.task_id == task_id).first()
        if task is None:
            raise HTTPException(status_code=404, detail="task not found")
        row = AppDvsFailureDebug(
            task_id=task_id,
            project_id=task.project_id,
            task_name=task.task_name,
            status="pending",
        )
        db.add(row)
        db.commit()
        created = True
    elif row.status in ("done", "running", "skipped"):
        return {"task_id": task_id, "status": row.status, "dispatched": False}
    elif row.status == "error":
        row.status = "pending"
        row.debug_error = None
        db.commit()
    # 唤醒 debugger worker（仅 debugger pod 上 FailureDebugService 已 start；非 debugger pod 是 no-op）
    try:
        from app.service.failure_debug import get_failure_debug_service
        get_failure_debug_service().submit(task_id)
    except Exception:
        pass
    return {"task_id": task_id, "status": row.status, "dispatched": True, "created": created}


def _row_to_dict(row: AppDvsFailureDebug, *, detail: bool = False) -> dict[str, Any]:
    d = {
        "id": row.id,
        "task_id": row.task_id,
        "project_id": row.project_id,
        "task_name": row.task_name,
        "status": row.status,
        "error_kind": row.error_kind,
        "failing_stage": row.failing_stage,
        "summary": row.summary,
        "report_path": row.report_path,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }
    if detail:
        d["report_json"] = row.report_json
        d["debug_error"] = row.debug_error
    return d


@router.get("/failure-debug-reports")
def list_failure_debug_reports(
    project_id: str | None = Query(None),
    status: str | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    q = select(AppDvsFailureDebug)
    if project_id:
        q = q.where(AppDvsFailureDebug.project_id == project_id)
    if status:
        q = q.where(AppDvsFailureDebug.status == status)

    count_q = select(func.count(AppDvsFailureDebug.id))
    if project_id:
        count_q = count_q.where(AppDvsFailureDebug.project_id == project_id)
    if status:
        count_q = count_q.where(AppDvsFailureDebug.status == status)
    total = int(db.execute(count_q).scalar() or 0)

    rows = (
        db.execute(
            q.order_by(AppDvsFailureDebug.created_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
        )
        .scalars()
        .all()
    )
    return {
        "items": [_row_to_dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.get("/failure-debug-reports/{report_id}")
def get_failure_debug_report(report_id: int, db: Session = Depends(get_db)):
    row = db.get(AppDvsFailureDebug, report_id)
    if not row:
        raise HTTPException(status_code=404, detail="report not found")
    return _row_to_dict(row, detail=True)


@router.get("/failure-debug-reports/{report_id}/download")
def download_failure_debug_report(report_id: int, db: Session = Depends(get_db)):
    row = db.get(AppDvsFailureDebug, report_id)
    if not row:
        raise HTTPException(status_code=404, detail="report not found")
    md_path = Path(row.report_path) if row.report_path else None
    if not md_path or not md_path.is_file():
        md_path = Path(OUTPUT_DIR) / row.task_id / "output" / "failure_debug_report.md"
    if not md_path.is_file():
        raise HTTPException(status_code=404, detail="report file not found on disk")
    content = md_path.read_bytes()
    filename = f"failure_debug_{row.task_id}.md"
    return Response(
        content=content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/failure-debug-reports/{report_id}")
def delete_failure_debug_report(report_id: int, db: Session = Depends(get_db)):
    """删除一条调试报告（表示已处理）。同时删除 NFS 上的报告文件。"""
    row = db.get(AppDvsFailureDebug, report_id)
    if not row:
        raise HTTPException(status_code=404, detail="report not found")
    task_id = row.task_id
    out_dir = Path(OUTPUT_DIR) / task_id / "output"
    for fname in ("failure_debug_report.md", "failure_debug_report.json"):
        try:
            (out_dir / fname).unlink(missing_ok=True)
        except Exception:
            pass
    db.delete(row)
    db.commit()
    return {"report_id": report_id, "deleted": True}
