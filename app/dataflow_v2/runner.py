"""dataflow-v2 任务入口 (debug 开关: TaskConfig.feature_flags["dataflow_v2"])。

当任务开启 feature_flags.dataflow_v2 时, task_service 用 DataflowV2Runner 替代 v1
Orchestrator。runner 兼容 v1 的 execute_recursive(task_id, _root_out_dir,
_root_output_dir) 接口 + _cancel_event 属性, 返回 TaskResult, 下游 (终态提交/
result.json) 无感。

后续测试完成后将全线切换 v2, 不保留 v1 (本 runner 即唯一入口)。
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Callable

from ..models import TaskConfig, TaskResult, TaskStatus
from .analysis import TaintAnalysisCallbacks
from .function_extractor import ensure_file_indexed
from .models import TaintParamInfo
from .orchestrator import DfsOrchestrator
from .store import DataflowStore

logger = logging.getLogger("dvs.dataflow_v2.runner")


class DataflowV2Runner:
    """v2 任务执行器, 对外接口与 v1 Orchestrator 兼容。"""

    def __init__(self, config: TaskConfig, on_event: Callable[..., None] | None = None,
                 task_id: str = "") -> None:
        self.cfg = config
        self.on_event = on_event or (lambda **kw: None)
        self.task_id = task_id
        self._cancel_event: threading.Event | None = threading.Event()

    def cancel(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()

    def execute_recursive(
        self,
        task_id: str | None = None,
        depth: int = 0,
        tainted_context: str = "",
        _analyzed: set[str] | None = None,
        _root_out_dir: Path | None = None,
        _root_output_dir: Path | None = None,
    ) -> TaskResult:
        tid = task_id or self.task_id
        cfg = self.cfg
        run_dir = Path(_root_out_dir) if _root_out_dir is not None else Path(cfg.output_dir) / tid / "run"
        v2_run_dir = run_dir / "dataflow-v2"
        sessions_dir = run_dir / "sessions"
        graph_db_path = run_dir / "vuln-scan.sqlite"
        vuln_root = run_dir / "vulnerabilities"
        source_root = cfg.cwd

        try:
            store = DataflowStore(v2_run_dir)
            # 1) 索引根函数所在文件
            if not cfg.source_file:
                return TaskResult(task_id=tid, status=TaskStatus.INVALID_INPUT,
                                  task=cfg.task, error="v2: source_file 未指定")
            ensure_file_indexed(source_root, cfg.source_file, store)
            root_func = store.find_function(cfg.function_name, cfg.source_file) \
                or store.find_function(cfg.function_name)
            if root_func is None:
                return TaskResult(task_id=tid, status=TaskStatus.INVALID_INPUT, task=cfg.task,
                                  error=f"v2: 根函数 {cfg.function_name} 未在 {cfg.source_file} 找到")

            # 2) 根污点参数 (位置 0..n-1 + 签名 + 名字)
            tp_names = cfg.taint_params or ["all"]
            root_taint = TaintParamInfo(
                positions=list(range(len(tp_names))),
                signature=",".join(tp_names),
                names=tp_names)

            # 3) 回调 + 编排器
            cbs = TaintAnalysisCallbacks(
                cfg=cfg, source_root=source_root, run_dir=v2_run_dir,
                sessions_dir=sessions_dir, graph_db_path=graph_db_path,
                vuln_root=vuln_root, run_id=tid, task_id=tid,
                cancel_event=self._cancel_event, on_event=self.on_event)
            orch = DfsOrchestrator(
                store, cbs, concurrent=True,
                max_concurrent_llm=max(1, int(getattr(cfg, "callee_concurrency", 4) or 4)))

            self.on_event(task_id=tid, event_type="v2_run_started",
                          function=cfg.function_name, source_file=cfg.source_file)
            orch.run(root_func, root_taint, base_session="")

            if self._cancel_event is not None and self._cancel_event.is_set():
                return TaskResult(task_id=tid, status=TaskStatus.FAILED, task=cfg.task,
                                  error="v2: cancelled")
            return TaskResult(
                task_id=tid, status=TaskStatus.PASSED, task=cfg.task,
                final_output="dataflow-v2 completed",
                vuln_summary={"functions": len(store.list_functions())})
        except Exception as exc:
            logger.exception("dataflow-v2 runner failed task=%s", tid)
            return TaskResult(task_id=tid, status=TaskStatus.ERROR, task=cfg.task, error=str(exc))
