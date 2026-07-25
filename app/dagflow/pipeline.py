"""dagflow 管线入口: taint 跟踪阶段 → 挖掘阶段。

feature_flags.dagflow_mode 开启时由 task_service 分流到此类。
独立于 dataflow_v2/ 完整模式 (DfsOrchestrator) 与自主模式 (AutonomousRunner)。
"""
from __future__ import annotations
import logging, sqlite3, threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

logger = logging.getLogger("dvs.dagflow.pipeline")


class FuncIndex:
    """函数索引查询 (读共享 functions.db, 复用 function_extractor 按需索引)。

    functions.db 由 function_extractor 填充 (共享基础设施, 非 V2 模式逻辑)。
    dagflow 只读 + 按需 extract callee 文件。
    """

    def __init__(self, source_root: str, functions_db: Path, dataflow_store: Any = None, mysql_store: Any = None) -> None:
        self.source_root = source_root
        self.db = functions_db
        self._v2_store = dataflow_store  # 用于 on-demand extract (写 functions.db); None=不按需
        self._mysql = mysql_store  # SharedMysqlStore (MySQL fallback)

    def get_by_name(self, name: str):
        """name (含类限定) -> FunctionRecord|None。"""
        # MySQL 优先
        if self._mysql:
            recs = self._mysql.read_functions(name)
            if recs: return recs[0]
        if not self.db.is_file():
            return None
        from ..dataflow_v2.models import FunctionRecord
        conn = sqlite3.connect(str(self.db), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            rows = conn.execute(
                "SELECT func_id,file,name,signature,start_line,end_line,description "
                "FROM functions WHERE name=?", (name,)).fetchall()
            return self._row_to_rec(rows[0]) if rows else self._ondemand(name)
        except sqlite3.Error as e:
            logger.warning("get_by_name sqlite query failed (name=%s): %s", name, e)
            return None
        finally:
            conn.close()

    def get_by_id(self, func_id: str):
        # MySQL 优先
        if self._mysql:
            rec = self._mysql.read_function(func_id)
            if rec: return rec
        if not self.db.is_file():
            return None
        conn = sqlite3.connect(str(self.db), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            rows = conn.execute(
                "SELECT func_id,file,name,signature,start_line,end_line,description "
                "FROM functions WHERE func_id=?", (func_id,)).fetchall()
            return self._row_to_rec(rows[0]) if rows else None
        except sqlite3.Error as e:
            logger.warning("get_by_id sqlite query failed (func_id=%s): %s", func_id, e)
            return None
        finally:
            conn.close()

    def _ondemand(self, name: str):
        """按需: 逐个文件 extract 直到函数被索引 (.h 只有声明, .c 才有定义)。"""
        if self._v2_store is None:
            logger.info("[ondemand] SKIP (v2_store is None): name=%s", name)
            return None
        from ..dataflow_v2.function_extractor import find_func_in_source, extract_file_functions
        hits = find_func_in_source(name, self.source_root)
        if not hits:
            logger.info("[ondemand] find_func_in_source returned no hits: name=%s", name)
            return None
        logger.info("[ondemand] found %d hits for %s, indexing...", len(hits), name)
        import sqlite3
        for rel_file, _ in hits:
            try:
                extract_file_functions(self.source_root, rel_file, self._v2_store)
            except Exception as e:
                logger.debug("ondemand extract %s failed: %s", rel_file, e)
                continue
            # MySQL 优先查 (extract 可能写到 MySQL)
            if self._mysql:
                try:
                    recs = self._mysql.read_functions(name)
                    if recs:
                        logger.info("[ondemand] %s found in MySQL after extract", name)
                        return recs[0]
                except Exception:
                    logger.warning("[ondemand] mysql read_functions failed name=%s", name, exc_info=True)
            # SQLite 回退
            conn = sqlite3.connect(str(self.db))
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    "SELECT func_id,file,name,signature,start_line,end_line,description "
                    "FROM functions WHERE name=?", (name,)).fetchall()
                if rows:
                    logger.info("[ondemand] %s found in SQLite after extract", name)
                    return self._row_to_rec(rows[0])
            except sqlite3.Error:
                logger.warning("[ondemand] sqlite lookup failed name=%s", name, exc_info=True)
            finally:
                conn.close()
        logger.info("[ondemand] %s not found after extracting %d files", name, len(hits))
        return None  # 所有文件都试过, 仍未索引

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
        # MySQL 共享存储 URL (从 config 取 db 配置)
        db_cfg = getattr(config, "db", None)
        self._mysql_url = db_cfg.url if db_cfg else \
            getattr(config, "mysql_url", "") or \
            "mysql+pymysql://root:Huawei12%23$@secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local:3306"

    def _emit(self, event_type: str, **kw) -> None:
        """安全发事件 (兼容现有 event 映射)。"""
        if self.on_event is None:
            return
        try:
            self.on_event(event_type, **kw)
        except Exception:
            logger.warning("dagflow pipeline emit failed event_type=%s task_id=%s", event_type, self.task_id, exc_info=True)

    def _create_mysql_graph_store(self):
        """创建 MysqlGraphStore (task_graph 双写, 失败返回 None)。"""
        try:
            from ..db.mysql_graph_store import create_mysql_graph_store
            pid = getattr(self.config, 'project_id', '') or ''
            return create_mysql_graph_store(self._mysql_url, project_id=pid)
        except Exception as e:
            logging.warning("create mysql graph store failed: %s", e)
            return None

    def abort(self):
        """取消任务 (与 V2 Orchestrator.abort 接口兼容)。"""
        if self.cancel_event is not None:
            self.cancel_event.set()

    def execute_recursive(self, task_id: str, *, _root_out_dir: str | None = None,
                          _root_output_dir: str | None = None) -> TaskResult:
        """阶段 1 taint 跟踪 -> 阶段 2 挖掘。返回 TaskResult (兼容 task_service model_dump)。"""
        from ..models import TaskResult, TaskStatus, TokenUsage
        from .dag_store import DagflowStore
        from ..db.shared_mysql import create_shared_store
        from .taint_analyzer import TaintAnalyzer
        from .orchestrator import DagflowOrchestrator
        from .trackers import TrackerDispatcher
        from . import trigger
        from .mining_agent import MiningAgent
        from ..vuln_store import VulnScanStore
        from ..dataflow_v2.function_extractor import extract_file_functions
        from .graph_recorder import GraphRecorder

        # _root_out_dir = epoch /tmp 路径 (symlink -> /tmp, 随 pod 消失)。
        # dagflow.db + vuln-scan.sqlite 放 NFS (持久, run/ 下), sessions/functions.db 留 epoch (与 V2 一致)。
        epoch_dir = Path(_root_out_dir or (Path(self.source_root) / "run"))
        # NFS run/ = epoch_dir.parent.parent (run/epochs/00NN -> run/epochs -> run/)
        nfs_run = epoch_dir.parent.parent if epoch_dir.name != "run" else epoch_dir
        # MySQL 共享存储 (双写, 失败不阻断)
        mysql_store = create_shared_store(
            self._mysql_url, "dagflow", self.source_root, task_id,
            project_id=getattr(self, 'task_id', '') and getattr(self.config, 'project_id', '') or '') \
            if hasattr(self, '_mysql_url') and self._mysql_url else None
        store = DagflowStore(nfs_run, mysql_store=mysql_store)  # dagflow.db -> run/dagflow/ (NFS, 持久)
        # 清空旧数据 (restart 时 dagflow.db 在 NFS 持久 + MySQL 双写, 需清两处防秒过)
        store._exec("DELETE FROM dag_processed_taints")
        store._exec("DELETE FROM taint_dag_nodes")
        store._exec("DELETE FROM taint_dag_edges")
        store._exec("DELETE FROM taint_dag_meta")
        if mysql_store:
            from sqlalchemy import text as sa_text
            params = {"sid": mysql_store.source_dir_id, "tid": mysql_store.task_id}
            for table in ['dag_processed_taints', 'dag_nodes', 'dag_edges', 'dag_meta']:
                try:
                    with mysql_store._engine.begin() as conn:
                        conn.execute(sa_text(
                            f"DELETE FROM {table} WHERE source_dir_id=:sid AND task_id=:tid"),
                            params)
                except Exception as e:
                    logger.debug("[dagflow] clear MySQL %s: %s", table, str(e)[:80])
            logger.info("[dagflow] cleared stale MySQL dag tables")
        logger.info("[dagflow] cleared stale dagflow.db data")
        sessions_dir = epoch_dir / "sessions"  # sessions -> epoch /tmp (与 V2 一致, 大文件 ephemeral)
        functions_db = epoch_dir / "dataflow-v2" / "functions.db"  # functions.db -> epoch (重建, 与 V2 一致)
        (epoch_dir / "dataflow-v2").mkdir(parents=True, exist_ok=True)
        # V2 DataflowStore 用于 function_extractor 按需索引 (共享, 不用其模式逻辑)
        v2_store = None
        try:
            from ..dataflow_v2.store import DataflowStore
            v2_store = DataflowStore(epoch_dir / "dataflow-v2", mysql_store=mysql_store)
            logger.info("[dagflow] v2_store OK: %s", epoch_dir / "dataflow-v2")
        except Exception as e:
            logger.warning("[dagflow] v2_store FAILED: %s", e)
        func_index = FuncIndex(self.source_root, functions_db, v2_store, mysql_store=mysql_store)

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
            # 诊断: 写 cfg 关键字段到 NFS
            try:
                from pathlib import Path as _P
                _diag = nfs_run / "dagflow_diag.txt"
                _diag.write_text(
                    f"cwd={getattr(self.config, 'cwd', '?')}\n"
                    f"source_file={getattr(self.config, 'source_file', '?')}\n"
                    f"function_name={getattr(self.config, 'function_name', '?')}\n"
                    f"source_root={self.source_root}\n"
                    f"agents={len(getattr(self.config.workers, 'agents', []))}\n"
                    f"agent_model={self.config.workers.agents[0].model if self.config.workers.agents else 'NONE'}\n"
                    f"feature_flags={getattr(self.config, 'feature_flags', {})}\n", encoding='utf-8')
            except Exception as e:
                logger.warning("diag write failed: %s", e)

            # ── graph recorder (兼容前端 graph-view API) ──
            vuln_db = nfs_run / "vuln-scan.sqlite"
            vuln_store = VulnScanStore(vuln_db, mysql_store=self._create_mysql_graph_store())
            epoch_name = epoch_dir.name  # e.g. "0006"
            graph_rec = GraphRecorder(vuln_store=vuln_store, task_id=task_id,
                                      epoch=epoch_name, run_root=str(nfs_run),
                                      root_function=root_name)
            graph_rec.start_run()

            # ── 阶段 1: taint 跟踪 ──
            logger.info("[dagflow] PHASE 1 START: taint tracking, root=%s", root_name)
            analyzer = TaintAnalyzer(config=self.config, sessions_dir=sessions_dir,
                                      on_event=self.on_event, task_id=task_id,
                                      func_lookup=func_index.get_by_name,
                                      graph_recorder=graph_rec)
            analyzer.cancel_event = self.cancel_event

            def analyze_fn(func, taint_sig, depth=0):
                analyzer._cur_depth = depth
                try:
                    dag, _sp = analyzer.analyze(func, taint_sig, is_auto=(taint_sig == "auto"))
                    return dag
                except Exception as e:
                    import traceback
                    from pathlib import Path as _P
                    _elog = nfs_run / "dagflow_analyze_errors.txt"
                    with open(_elog, "a", encoding="utf-8") as _f:
                        _f.write(f"=== analyze_fn FAILED func={func.name} taint={taint_sig} depth={depth} ===\n")
                        _f.write(traceback.format_exc())
                        _f.write("\n")
                    raise

            # tracker reader_finder/function_resolver: LLM+v2_db 找读者/解析间接 (生产实现)
            from .reader_finder import ReaderFinder
            from .function_resolver import FunctionResolver
            v2_db_dir = epoch_dir / "dataflow-v2"
            rf = ReaderFinder(config=self.config, source_root=self.source_root,
                              v2_db_dir=v2_db_dir, sessions_dir=sessions_dir,
                              task_id=task_id, on_event=self.on_event,
                              cancel_event=self.cancel_event,
                              graph_recorder=graph_rec)
            fr_ = FunctionResolver(config=self.config, source_root=self.source_root,
                                   v2_db_dir=v2_db_dir, sessions_dir=sessions_dir,
                                   task_id=task_id, on_event=self.on_event,
                                   cancel_event=self.cancel_event,
                                   func_lookup_by_id=func_index.get_by_id,
                                   graph_recorder=graph_rec)
            dispatcher = TrackerDispatcher(
                store=store, func_lookup=func_index.get_by_name,
                func_lookup_by_id=func_index.get_by_id,
                on_enqueue=lambda fid, t: orch._wq.put(_make_callee_item(fid, t)),
                on_event=self.on_event,
                reader_finder=rf.find, function_resolver=fr_.resolve)
            # 暴露 orch 给 on_enqueue (run 后可用)
            orch = DagflowOrchestrator(
                store=store, analyze_fn=analyze_fn,
                func_lookup=func_index.get_by_name, on_event=self.on_event,
                n_workers=max(1, int(getattr(self.config, "callee_concurrency", 4) or 4)),  # DAG 会话比 V2 轻, 并发度 >= V2
                task_id=task_id, cancel_event=self.cancel_event,
                tracker_dispatcher=dispatcher, graph_recorder=graph_rec)
            orch._func_lookup_by_id = func_index.get_by_id

            taints = getattr(self.config, "taint_details", []) or [{"name": "auto"}]
            if root_func is not None:
                for td in taints:
                    tn = str(td.get("name", "auto")).strip() or "auto"
                    orch.run(root_func, tn)
                logger.info("[dagflow] PHASE 1 DONE: analyzed=%d", len(store.list_analyzed()))
                self._emit("v2_dagflow_phase", phase="tracking_done",
                           analyzed=len(store.list_analyzed()), task_id=task_id)
            else:
                self._emit("v2_dagflow_phase", phase="no_root_func",
                           root=root_name, task_id=task_id)

            # ── 阶段 2: 挖掘 (传出点就绪的 (func,taint)) ──
            logger.info("[dagflow] PHASE 2 START: vuln mining, candidates=%d", len(list(store.list_analyzed())))
            miner = MiningAgent(config=self.config, store=store, sessions_dir=sessions_dir,
                                vuln_store=vuln_store, run_id=task_id,
                                func_lookup=func_index.get_by_name,
                                on_event=self.on_event, task_id=task_id,
                                graph_recorder=graph_rec)
            miner.cancel_event = self.cancel_event
            total_findings = 0
            # 多轮: 跟踪产新 DAG 后传出点就绪状态变化; 简化为单轮 (跟踪完成后挖一轮)
            # 挖掘会话互相独立 (每个 (func,taint) 独立 agent), 可并行 (设计 §10)
            _mine_workers = max(1, int(getattr(self.config, "callee_concurrency", 4) or 4))
            _mine_lock = threading.Lock()
            _candidates = []
            for fid, ts in list(store.list_analyzed()):
                func = func_index.get_by_id(fid)
                if func is None:
                    logger.warning("[dagflow-mine] SKIP (func not indexed): fid=%s taint=%s", fid[:12], ts)
                    continue
                if trigger.is_ready(store, fid, ts, func_index.get_by_name):
                    _candidates.append((func, ts))
            def _mine_one(args):
                func, ts = args
                try:
                    fs = miner.mine(func, ts)
                    with _mine_lock:
                        nonlocal_ref[0] += len(fs)
                except Exception as e:
                    logger.exception("mine %s/%s failed: %s", func.name, ts, e)
            nonlocal_ref = [0]
            with ThreadPoolExecutor(max_workers=_mine_workers) as pool:
                list(pool.map(_mine_one, _candidates))
            total_findings = nonlocal_ref[0]
            logger.info("[dagflow] PHASE 2 DONE: findings=%d", total_findings)
            self._emit("v2_dagflow_phase", phase="mining_done", findings=total_findings, task_id=task_id)
            self._emit("task_end", task_id=task_id)
            graph_rec.finish_run("passed")
            return TaskResult(
                task_id=task_id, status=TaskStatus.PASSED, task=self.config.task,
                analysis_status="dagflow_complete",
                completion_reason="dagflow tracking + mining 完成",
                vuln_summary={"pipeline": "dagflow", "analyzed": len(store.list_analyzed()),
                              "findings": total_findings},
                total_tokens=TokenUsage(),
            )
        except Exception as e:
            logger.exception("dagflow pipeline error: %s", e)
            return TaskResult(
                task_id=task_id, status=TaskStatus.ERROR, task=getattr(self.config, "task", ""),
                analysis_status="error", completion_reason=str(e),
                error=str(e), total_tokens=TokenUsage(),
            )
        finally:
            store.close()
            if v2_store is not None:
                try:
                    v2_store.close()
                except Exception:
                    logger.warning("close v2_store failed in dagflow pipeline", exc_info=True)


def _make_callee_item(func_id, taint):
    from .models import WorkItem
    return WorkItem(kind="callee", target_func=func_id, target_taint=taint,
                    origin_func="(tracker)", origin_node=-1, origin_edge="(tracker)")
