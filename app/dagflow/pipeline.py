"""dagflow 管线入口 (P1 脚手架)。

与 V2 Orchestrator 同接口: execute_recursive(task_id, _root_out_dir, _root_output_dir)。
feature_flags.dagflow_mode 开启时由 task_service 分流到此类。
P1: 空实现, 仅打事件 + 返回; 验证开关不影响现有完整/自主模式。
后续 P2-P6 填充: taint 跟踪阶段 (队列驱动产 DAG) → 挖掘阶段 (正向建链 + D1-D4)。
"""
from __future__ import annotations
from typing import Any


class DagflowPipeline:
    """dagflow 管线 (DAG 污点跟踪 + 正向建链挖掘)。

    独立于 dataflow_v2/ 完整模式 (DfsOrchestrator) 与自主模式 (AutonomousRunner)。
    """

    def __init__(self, *, config: Any, on_event: Any, task_id: str) -> None:
        self.config = config
        self.on_event = on_event
        self.task_id = task_id

    def execute_recursive(self, task_id: str, *, _root_out_dir: str | None = None,
                          _root_output_dir: str | None = None) -> dict:
        """P1 脚手架: 发 task_start/task_end 事件, 返回占位结果。

        后续阶段在此编排:
          阶段 1 (taint 跟踪): work_queue BFS → 每 (func,taint) analyze 产 DAG →
                  发跟入项 → tracker (escape 中继 / indirect) → 重放拼接
          阶段 2 (挖掘): trigger (传出点就绪) → chain_builder 正向建链 →
                  mining_agent D1-D4 → finding_store 去重上报
        """
        # 发事件 (兼容现有 event 映射)
        try:
            self.on_event("task_start", task_id=self.task_id)
        except Exception:
            pass
        try:
            self.on_event("v2_dagflow_phase", phase="scaffold", task_id=self.task_id,
                          note="dagflow P1 scaffold: 后续填 taint 跟踪 + 挖掘")
        except Exception:
            pass
        try:
            self.on_event("task_end", task_id=self.task_id)
        except Exception:
            pass
        return {"task_id": self.task_id, "status": "done", "pipeline": "dagflow", "phase": "scaffold"}
