"""dagflow 管线入口: taint 跟踪阶段 → 挖掘阶段。

feature_flags.dagflow_mode 开启时由 task_service 分流到此类。
独立于 dataflow_v2/ 完整模式 (DfsOrchestrator) 与自主模式 (AutonomousRunner)。
"""
from __future__ import annotations
import logging, sqlite3, threading
from pathlib import Path
from typing import Any

logger = logging.getLogger("dvs.dagflow.pipeline")


class FuncIndex:
    """函数索引查询 (读共享 functions.db, 复用 function_extractor 按需索引)。

    functions.db 由 function_extractor 填充 (共享基础设施, 非 V2 模式逻辑)。
    dagflow 只读 + 按需 extract callee 文件。
    """

    def __init__(self, source_root: str, functions_db: Path, dataflow_store: Any = None) -> None:
        self.source_root = source_root
        self.db = functions_db
        self._v2_store = dataflow_store  # 用于 on-demand extract (写 functions.db); None=不按需

    def get_by_name(self, name: str):
        """name (含类限定) -> FunctionRecord|None。"""
        if not self.db.is_file():
            return None
        from ..dataflow_v2.models import FunctionRecord
        conn = sqlite3.connect(str(self.db))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT func_id,file,name,signature,start_line,end_line,description "
                "FROM functions WHERE name=?", (name,)).fetchall()
            return self._row_to_rec(rows[0]) if rows else self._ondemand(name)
        except sqlite3.Error:
            return None
        finally:
            conn.close()

    def get_by_id(self, func_id: str):
        if not self.db.is_file():
            return None
        conn = sqlite3.connect(str(self.db))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT func_id,file,name,signature,start_line,end_line,description "
                "FROM functions WHERE func_id=?", (func_id,)).fetchall()
            return self._row_to_rec(rows[0]) if rows else None
        except sqlite3.Error:
            return None
        finally:
            conn.close()

    def _ondemand(self, name: str):
        """按需: 用 function_extractor 全项目搜该函数 (写 functions.db)。P6 stub: 返回 None。"""
        # 完整 on-demand 搜索较重; P6 先返回 None (callee 未索引则跳过, tracker/挖掘按未知处理)
        return None

    @staticmethod
    def _row_to_rec(r):
        from ..dataflow_v2.models import FunctionRecord
        rec = FunctionRecord(file=r["file"], name=r["name"], signature=r["signature"],
                             start_line=r["start_line"], end_line=r["end_line"])
        rec.func_id = r["func_id"]
        rec.description = r["description"] or ""
        return rec


class DagflowPipeline:
    """dagflow 管线 (DAG 污点跟踪 + 正向建链挖掘)。

    execute_recursive 同 V2 Orchestrator 接口 (task_service 调)。
    """

    def __init__(self, *, config: Any, on_event: Any, task_id: str) -> None:
        self.config = config
        self.on_event = on_event
        self.task_id = task_id
        self.source_root = getattr(config, "cwd", "") or getattr(config, "source_root", "")
        self.cancel_event = None

    def execute_recursive(self, task_id: str, *, _root_out_dir: str | None = None,
                          _root_output_dir: str | None = None) -> dict:
        """阶段 1 taint 跟踪 -> 阶段 2 挖掘。"""
        from .dag_store import DagflowStore
        from .taint_analyzer import TaintAnalyzer
        from .line_filler import fill_lines
        from .orchestrator import DagflowOrchestrator
        from .trackers import TrackerDispatcher
        from . import trigger
        from .mining_agent import MiningAgent
        from ..vuln_store import VulnScanStore
        from ..dataflow_v2.function_extractor import extract_file_functions

        run_dir = Path(_root_out_dir or (Path(self.source_root) / "run"))
        store = DagflowStore(run_dir)
        sessions_dir = run_dir / "sessions"
        functions_db = run_dir / "dataflow-v2" / "functions.db"  # 共享 functions.db
        (run_dir / "dataflow-v2").mkdir(parents=True, exist_ok=True)
        # V2 DataflowStore 用于 function_extractor 按需索引 (共享, 不用其模式逻辑)
        v2_store = None
        try:
            from ..dataflow_v2.store import DataflowStore
            v2_store = DataflowStore(run_dir / "dataflow-v2")
        except Exception:
            pass
        func_index = FuncIndex(self.source_root, functions_db, v2_store)

        # 索引根函数所在文件 (function_extractor 填 functions.db)
        src_file = getattr(self.config, "source_file", "")
        root_name = getattr(self.config, "function_name", "")
        if src_file and v2_store is not None:
            try:
                extract_file_functions(self.source_root, src_file, v2_store)
            except Exception as e:
                logger.warning("extract root file failed: %s", e)

        root_func = func_index.get_by_name(root_name) if root_name else None

        try:
            self._emit("task_start", task_id=task_id)

            # ── 阶段 1: taint 跟踪 ──
            analyzer = TaintAnalyzer(config=self.config, sessions_dir=sessions_dir,
                                      on_event=self.on_event, task_id=task_id)
            analyzer.cancel_event = self.cancel_event

            def analyze_fn(func, taint_sig):
                dag, _sp = analyzer.analyze(func, taint_sig, is_auto=(taint_sig == "auto"))
                fill_lines(dag, func, self.source_root)
                return dag

            # tracker reader_finder/function_resolver: P6 stub (返回 [], 不解析; 后续 LLM+v2_db 填)
            dispatcher = TrackerDispatcher(
                store=store, func_lookup=func_index.get_by_name,
                on_enqueue=lambda fid, t: orch._wq.put(_make_callee_item(fid, t)),
                on_event=self.on_event)
            # 暴露 orch 给 on_enqueue (run 后可用)
            orch = DagflowOrchestrator(
                store=store, analyze_fn=analyze_fn,
                func_lookup=func_index.get_by_name, on_event=self.on_event,
                n_workers=getattr(self.config, "callee_concurrency", 4) or 4,
                task_id=task_id, cancel_event=self.cancel_event,
                tracker_dispatcher=dispatcher)
            orch._func_lookup_by_id = func_index.get_by_id

            taints = getattr(self.config, "taint_details", []) or [{"name": "auto"}]
            if root_func is not None:
                for td in taints:
                    tn = str(td.get("name", "auto")).strip() or "auto"
                    orch.run(root_func, tn)
                self._emit("v2_dagflow_phase", phase="tracking_done",
                           analyzed=len(store.list_analyzed()), task_id=task_id)
            else:
                self._emit("v2_dagflow_phase", phase="no_root_func",
                           root=root_name, task_id=task_id)

            # ── 阶段 2: 挖掘 (传出点就绪的 (func,taint)) ──
            vuln_db = run_dir / "vuln-scan.sqlite"
            vuln_store = VulnScanStore(vuln_db)
            miner = MiningAgent(config=self.config, store=store, sessions_dir=sessions_dir,
                                vuln_store=vuln_store, run_id=task_id,
                                func_lookup=func_index.get_by_name,
                                on_event=self.on_event, task_id=task_id)
            miner.cancel_event = self.cancel_event
            total_findings = 0
            # 多轮: 跟踪产新 DAG 后传出点就绪状态变化; 简化为单轮 (跟踪完成后挖一轮)
            for fid, ts in list(store.list_analyzed()):
                func = func_index.get_by_id(fid)
                if func is None:
                    continue
                if trigger.is_ready(store, fid, ts, func_index.get_by_name):
                    try:
                        fs = miner.mine(func, ts)
                        total_findings += len(fs)
                    except Exception as e:
                        logger.exception("mine %s/%s failed: %s", func.name, ts, e)
            self._emit("v2_dagflow_phase", phase="mining_done", findings=total_findings, task_id=task_id)
            self._emit("task_end", task_id=task_id)
            return {"task_id": task_id, "status": "done", "pipeline": "dagflow",
                    "analyzed": len(store.list_analyzed()), "findings": total_findings}
        finally:
            store.close()
            if v2_store is not None:
                try: v2_store.close()
                except Exception: pass


def _make_callee_item(func_id, taint):
    from .models import WorkItem
    return WorkItem(kind="callee", target_func=func_id, target_taint=taint,
                    origin_func="(tracker)", origin_node=-1, origin_edge="(tracker)")
