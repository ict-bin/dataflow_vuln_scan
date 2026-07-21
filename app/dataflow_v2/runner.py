"""dataflow-v2 任务入口 (debug 开关: TaskConfig.feature_flags["dataflow_v2"])。

当任务开启 feature_flags.dataflow_v2 时, task_service 用 DataflowV2Runner 替代 v1
Orchestrator。runner 兼容 v1 的 execute_recursive(task_id, _root_out_dir,
_root_output_dir) 接口 + _cancel_event 属性, 返回 TaskResult, 下游 (终态提交/
result.json) 无感。

后续测试完成后将全线切换 v2, 不保留 v1 (本 runner 即唯一入口)。
"""
from __future__ import annotations

import json
import logging
import shutil
import threading
from pathlib import Path
from typing import Any, Callable

from ..copy_utils import safe_copy2
from ..models import SwarmEvent, TaskConfig, TaskResult, TaskStatus
from ..vuln_store import TaskGraphRunRecord, VulnScanStore
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
        self._raw_on_event = on_event
        self.task_id = task_id
        self._cancel_event: threading.Event | None = threading.Event()

    def _create_mysql_store(self, mode: str):
        """创建 SharedMysqlStore (双写, 失败返回 None)。"""
        try:
            from ..db.shared_mysql import create_shared_store
            db_cfg = getattr(self.cfg, "db", None)
            url = db_cfg.url if db_cfg else \
                "mysql+pymysql://root:Huawei12%23$@secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local:3306"
            project_id = getattr(self.cfg, "project_id", "") or ""
            return create_shared_store(url, mode, self.cfg.cwd, self.task_id, project_id=project_id)
        except Exception as e:
            logger.warning("create mysql store failed: %s", e)
            return None

    def _create_mysql_graph_store(self):
        """创建 MysqlGraphStore (task_graph 双写, 失败返回 None)。"""
        try:
            from ..db.mysql_graph_store import create_mysql_graph_store
            db_cfg = getattr(self.cfg, "db", None)
            url = db_cfg.url if db_cfg else \
                "mysql+pymysql://root:Huawei12%23$@secflow-app-dataflow-vuln-scan-mysql.secflow-ns.svc.cluster.local:3306"
            project_id = getattr(self.cfg, "project_id", "") or ""
            source_root = self.cfg.cwd
            import hashlib
            sid = hashlib.sha1(source_root.encode("utf-8")).hexdigest()[:16]
            return create_mysql_graph_store(url, project_id=project_id,
                                             source_dir_id=sid, source_root=source_root)
        except Exception as e:
            logger.warning("create mysql graph store failed: %s", e)
            return None

    def _emit(self, etype: str, **data: Any) -> None:
        """适配: (etype, **data) → SwarmEvent → task_service on_event(SwarmEvent)。"""
        try:
            if self._raw_on_event is not None:
                self._raw_on_event(SwarmEvent(type=etype, task_id=self.task_id, data=data))
        except Exception:
            logger.debug("v2 _emit %s failed", etype, exc_info=True)

    def abort(self) -> None:
        """取消任务 (与 v1 Orchestrator.abort 接口兼容)。"""
        if self._cancel_event is not None:
            self._cancel_event.set()

    def cancel(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()

    @property
    def on_event(self) -> Callable[..., None]:
        """callbacks 收到的 emit 接口 (etype, **data)。"""
        return self._emit

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
        # DB 放 epoch 目录 (通过 workspace_manager symlink → pod 本地)
        # NFS 只做归档同步 (workspace_manager sync_back_and_cleanup)
        if _root_out_dir is not None:
            root_out_dir = Path(_root_out_dir)
            # shared_run_dir 用于 output/ 路径计算 (NFS)
            shared_run_dir = root_out_dir.parent.parent if ("epochs" in root_out_dir.parts and "run" in root_out_dir.parts) else root_out_dir
        else:
            root_out_dir = Path(cfg.output_dir) / tid / "run"
            shared_run_dir = root_out_dir
        root_out_dir.mkdir(parents=True, exist_ok=True)
        root_output_path = Path(_root_output_dir) if _root_output_dir is not None else (shared_run_dir.parent / "output")
        root_output_path.mkdir(parents=True, exist_ok=True)
        # DB 放 root_out_dir (epoch 目录, 通过 symlink → 本地存储)
        v2_run_dir = root_out_dir / "dataflow-v2"
        sessions_dir = root_out_dir / "sessions"
        graph_db_path = root_out_dir / "vuln-scan.sqlite"
        vuln_root = root_out_dir / "vulnerabilities"
        source_root = cfg.cwd
        status = TaskStatus.PASSED
        err_msg = ""

        try:
            store = DataflowStore(v2_run_dir, mysql_store=self._create_mysql_store("complete"))
            # 增量索引: 只索引根函数所在文件 (不全量扫描)
            # 分析过程中 callee 查不到时用 v2_db index <file> 增量索引
            self._emit("v2_indexing_source_tree")
            ensure_file_indexed(source_root, cfg.source_file, store)
            self._emit("v2_indexed", functions=store.count_functions())
            if not cfg.source_file:
                return TaskResult(task_id=tid, status=TaskStatus.INVALID_INPUT,
                                  task=cfg.task, error="v2: source_file 未指定")
            root_func = store.find_function(cfg.function_name, cfg.source_file) \
                or store.find_function(cfg.function_name)
            # .h 文件只有声明没有定义 → grep 搜索同名函数的 .cpp 定义文件
            if root_func is None:
                from .function_extractor import find_func_in_source, ensure_file_indexed as _ensure
                src = Path(source_root)
                found = find_func_in_source(cfg.function_name, src)
                if found:
                    for rel_def_file, _ in found:
                        _ensure(source_root, rel_def_file, store)
                    root_func = store.find_function(cfg.function_name, rel_def_file) \
                        or store.find_function(cfg.function_name)
            if root_func is None:
                return TaskResult(task_id=tid, status=TaskStatus.INVALID_INPUT, task=cfg.task,
                                  error=f"v2: 根函数 {cfg.function_name} 未在 {cfg.source_file} 找到")

            # 2) 根污点参数
            #    EA 给了具体 taint_params → 直接用
            #    EA 没给 → 标记为 "auto", prompt 告知 LLM 自行分析所有入参 + 内部调用产生的污点
            #    EA 传了非法值 (纯数字/非标识符) → 回退 auto, 防 LLM 找不到变量导致 0 传播
            import re as _re
            _VALID_IDENT = _re.compile(r'^[A-Za-z_][\w:.<>\[\]*-]*$')
            if cfg.taint_params and all(_VALID_IDENT.match(str(p).strip()) for p in cfg.taint_params):
                tp_names = [str(p).strip() for p in cfg.taint_params]
                root_taint = TaintParamInfo(
                    positions=list(range(len(tp_names))),
                    signature=",".join(tp_names),
                    names=tp_names)
            else:
                # EA 未指定污点: LLM 自行识别
                root_taint = TaintParamInfo(
                    positions=[],  # 空 = 不限定位置, LLM 自行判断
                    signature="auto",
                    names=["auto"])

            # 3) 回调 + 编排器
            cbs = TaintAnalysisCallbacks(
                cfg=cfg, source_root=source_root, run_dir=v2_run_dir,
                sessions_dir=sessions_dir, graph_db_path=graph_db_path,
                vuln_root=vuln_root, run_id=tid, task_id=tid,
                cancel_event=self._cancel_event, on_event=self.on_event)
            cbs.graph_store._mysql = self._create_mysql_graph_store()
            cbs.graph_store.start_run(tid, tid, cfg.source_file or "", cfg.function_name or "", source_root, {})
            cbs.graph_store.start_task_graph_run(TaskGraphRunRecord(
                task_id=tid,
                epoch=cbs.graph_epoch,
                run_root=str(root_out_dir),
                root_function=cfg.function_name or "",
            ))
            # 配置沿用 v1: deep_trace_enabled=无限深度; callee_concurrency -1=auto(4)/1=串行/N
            _cc = int(getattr(cfg, "callee_concurrency", 4) or 4)
            _concurrent = (_cc != 1)
            _max_llm = 4 if _cc in (-1, 0) else max(1, _cc)
            _max_depth = 10**9 if getattr(cfg, "deep_trace_enabled", False) else int(getattr(cfg, "max_trace_depth", 10) or 10)
            orch = DfsOrchestrator(
                store, cbs, concurrent=_concurrent,
                max_concurrent_llm=_max_llm, max_depth=_max_depth)

            self._emit("v2_run_started", function=cfg.function_name, source_file=cfg.source_file)
            orch.run(root_func, root_taint, base_session="")

            if self._cancel_event is not None and self._cancel_event.is_set():
                status, err_msg = TaskStatus.FAILED, "v2: cancelled"
            else:
                # 0 传播边: 检查是否有 taint 分析成功
                # self_contained=True 的函数不需要跟入 callee, 有 vuln mining 就是正常完成
                # propagations.db 有记录但 target_func_id 为空 (callee 找不到) 也是正常分析
                try:
                    _edge_count = store._q("orchestration", "SELECT count(*) FROM orchestration")
                    _edge_count = int(_edge_count[0][0]) if _edge_count else 0
                except Exception:
                    _edge_count = 0
                try:
                    _prop_count = store._q("propagations", "SELECT count(*) FROM propagations")
                    _prop_count = int(_prop_count[0][0]) if _prop_count else 0
                except Exception:
                    _prop_count = 0
                if _edge_count == 0 and _prop_count == 0:
                    # 0 传播边 + 0 传播记录: 区分"解析失败" vs "解析成功但无传播"
                    # taints > 0 说明 LLM 成功分析了函数, 识别了污点, 但未报告任何传播路径
                    # taints == 0 说明 LLM 解析失败或未识别污点 (真失败)
                    try:
                        _taint_count = store._q("taints", "SELECT count(*) FROM taints")
                        _taint_count = int(_taint_count[0][0]) if _taint_count else 0
                    except Exception:
                        _taint_count = 0
                    if _taint_count > 0:
                        # 解析成功, 有污点但无传播 = LLM 判定无传播路径 (可能漏报)
                        status = TaskStatus.COMPLETED_LIMITED
                        err_msg = "v2: taint 分析未产出传播边 (LLM 识别了污点但未报告传播路径, 可能漏报)"
                    else:
                        # 无污点也无传播: 用根函数状态区分
                        #   root_analyzed=False -> 根被跳过 (processed_taints 残留/占位冲突, LLM 没跑)
                        #   root_taint_failed=True  -> 解析失败/格式错误 (真失败)
                        #   root_taint_failed=False -> LLM 合法返回空, 判定无可跟踪污点
                        _root_analyzed = bool(getattr(orch, "root_analyzed", False))
                        _root_failed = bool(getattr(orch, "root_taint_failed", False))
                        status = TaskStatus.COMPLETED_LIMITED
                        if not _root_analyzed:
                            err_msg = "v2: taint 分析未产出传播边 (根函数未执行分析, 可能 processed_taints 残留/占位冲突)"
                        elif _root_failed:
                            err_msg = "v2: taint 分析未产出传播边 (LLM 输出可能截断或格式错误)"
                        else:
                            err_msg = "v2: taint 分析未产出传播边 (LLM 判定无可跟踪污点, 合法空结果)"
                # else: 有 propagation 记录但 edge_count=0 (callee 找不到/不跟入) = 正常完成
            final_output = self._build_final_report(tid, cfg, store, graph_db_path)
            vuln_summary = {"functions": store.count_functions(),
                            "findings": self._count_findings(graph_db_path)}
            graph_run_status = "cancelled" if (self._cancel_event is not None and self._cancel_event.is_set()) else str(status.value if hasattr(status, "value") else status)
            cbs.graph_store.finish_run(tid, graph_run_status)
            result = TaskResult(task_id=tid, status=status, task=cfg.task,
                                final_output=final_output, vuln_summary=vuln_summary, error=err_msg or None)
            # 归档: 与 v1 一致的 output/ 件 + v2 四库归档; 不写 flag
            self._archive(root_out_dir, shared_run_dir, root_output_path, result, v2_run_dir,
                          graph_db_path, vuln_root)
            return result
        except Exception as exc:
            logger.exception("dataflow-v2 runner failed task=%s", tid)
            try:
                VulnScanStore(graph_db_path).finish_run(
                    tid,
                    "cancelled" if (self._cancel_event is not None and self._cancel_event.is_set()) else "error",
                )
            except Exception:
                pass
            return TaskResult(task_id=tid, status=TaskStatus.ERROR, task=cfg.task, error=str(exc))

    # ── 归档 (镜像 v1 output/ 件 + v2 四库归档, 不写 flag) ────────────────────
    def _archive(self, root_out_dir: Path, shared_run_dir: Path, root_output_path: Path,
                 result: TaskResult, v2_run_dir: Path, graph_db_path: Path, vuln_root: Path) -> None:
        # run/report.md + run/result.json (与 v1 一致)
        try:
            (root_out_dir / "report.md").write_text(result.final_output or "", encoding="utf-8")
            (root_out_dir / "result.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")
        except OSError:
            pass
        # output/final_report.md
        try:
            (root_output_path / "final_report.md").write_text(result.final_output or "", encoding="utf-8")
        except OSError:
            pass
        # output/vuln-scan.sqlite (findings 图谱)
        if graph_db_path.exists():
            try:
                safe_copy2(graph_db_path, root_output_path / "vuln-scan.sqlite")
            except OSError as e:
                logger.warning("v2 archive vuln-scan.sqlite: %s", e)
        # output/vulnerabilities/ (漏洞报告目录)
        if vuln_root.exists():
            try:
                dst = root_output_path / "vulnerabilities"
                if dst.exists():
                    shutil.rmtree(dst)
                shutil.copytree(vuln_root, dst)
            except OSError as e:
                logger.warning("v2 archive vulnerabilities: %s", e)
        # output/dataflow-v2/ (归档 v2 四库 + functions/ + clang-cache/)
        if v2_run_dir.exists():
            try:
                dst = root_output_path / "dataflow-v2"
                if dst.exists():
                    shutil.rmtree(dst)
                shutil.copytree(v2_run_dir, dst)
            except OSError as e:
                logger.warning("v2 archive dataflow-v2 db: %s", e)
        # output/sessions/ — keep the same directory alive during runtime and
        # reconcile incrementally here instead of deleting/recreating it.
        sessions_src = root_out_dir / "sessions"
        if sessions_src.exists():
            try:
                dst = root_output_path / "sessions"
                self._sync_session_tree(sessions_src, dst)
            except OSError as e:
                logger.warning("v2 archive sessions: %s", e)
        # output/artifact-manifest.json (v2 件清单)
        manifest = [
            {"stage": "dataflow_v2", "kind": "markdown", "role": "final_report", "path": str(root_output_path / "final_report.md")},
            {"stage": "dataflow_v2", "kind": "sqlite", "role": "vuln_graph", "path": str(root_output_path / "vuln-scan.sqlite")},
            {"stage": "dataflow_v2", "kind": "directory", "role": "vulnerabilities", "path": str(root_output_path / "vulnerabilities")},
            {"stage": "dataflow_v2", "kind": "directory", "role": "dataflow_v2_db", "path": str(root_output_path / "dataflow-v2")},
            {"stage": "dataflow_v2", "kind": "directory", "role": "sessions", "path": str(root_output_path / "sessions")},
        ]
        try:
            (root_output_path / "artifact-manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            pass
        # 不写 flag 文件 (已废弃)

    def _sync_session_tree(self, sessions_src: Path, sessions_dst: Path) -> None:
        sessions_dst.mkdir(parents=True, exist_ok=True)
        seen: set[Path] = set()
        for src in sessions_src.rglob("*"):
            rel = src.relative_to(sessions_src)
            dst = sessions_dst / rel
            seen.add(rel)
            if src.is_dir():
                dst.mkdir(parents=True, exist_ok=True)
                continue
            if not src.is_file():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            safe_copy2(src, dst)
        for dst in sorted(sessions_dst.rglob("*"), reverse=True):
            rel = dst.relative_to(sessions_dst)
            if rel in seen:
                continue
            try:
                if dst.is_dir():
                    dst.rmdir()
                else:
                    dst.unlink()
            except OSError:
                logger.debug("v2 archive sessions cleanup skip %s", dst, exc_info=True)

    def _build_final_report(self, tid: str, cfg: TaskConfig, store: DataflowStore,
                            graph_db_path: Path) -> str:
        """构建最终报告 (漏洞简报列表, 与 v1 _report 风格一致)。"""
        findings = []
        if graph_db_path.exists():
            try:
                findings = VulnScanStore(graph_db_path).list_all_findings()
            except Exception:
                findings = []
        lines = [
            f"# 数据流漏洞挖掘简报 (v2): {cfg.function_name}",
            "",
            "## 结果概览",
            "",
            f"- 任务ID: `{tid}`",
            f"- 状态: `{TaskStatus.PASSED.value}`",
            f"- 漏洞数量: {len(findings)}",
            f"- 函数库函数数: {store.count_functions()}",
            f"- 图谱数据库: `output/vuln-scan.sqlite`",
            f"- v2 四库: `output/dataflow-v2/`",
            "",
            "## 漏洞简报列表",
            "",
        ]
        if not findings:
            lines.append("未确认漏洞发现。")
        else:
            for idx, item in enumerate(findings, 1):
                lines += [
                    f"### {idx}. {item.get('title') or item.get('finding_id')}",
                    "",
                    f"- ID: `{item.get('finding_id')}`",
                    f"- 所在文件: `{item.get('source_file') or ''}`",
                    f"- 所在函数: `{item.get('function_name') or ''}`",
                    f"- 所在行号: `{item.get('line') or 'unknown'}`",
                    f"- 漏洞类型: `{item.get('vuln_type') or 'unknown'}`",
                    f"- 严重程度: `{item.get('severity') or 'unknown'}`",
                    f"- 置信度: `{item.get('confidence')}`",
                    f"- 概述: {item.get('summary') or ''}",
                    "",
                ]
        return "\n".join(lines).strip() + "\n"

    def _count_findings(self, graph_db_path: Path) -> int:
        if not graph_db_path.exists():
            return 0
        try:
            return len(VulnScanStore(graph_db_path).list_all_findings())
        except Exception:
            return 0
