"""Architectural workflow for dataflow taint tracking + vulnerability mining.

This module is intentionally separated from the legacy PerTaintWorkflow so the
new service can evolve independently:

  analyze-function-context  -> records taint edges/followups into SQLite
  fork vuln-mining-context  -> detects in-function vulnerabilities
  queue/fork followup funcs -> recursively continues taint tracking

The first implementation is additive: it creates the SQLite graph, exports
structured artifacts, and then delegates the mature per-taint function analysis to
PerTaintWorkflow.  Prompt/skill files added in this change specify the stronger
JSON contracts that later iterations can enforce strictly.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Any

from .models import CalleeRef, SwarmEvent, TaskConfig, TaskResult
from .runner import run_agent
from .taint_workflow import PerTaintWorkflow
from .vuln_store import (
    FollowupRecord,
    TaintEdgeRecord,
    TaintSourceRecord,
    VulnFindingRecord,
    VulnScanStore,
)
from .vuln_graph_validator import validate_taint_graph


@dataclass
class TaintInput:
    symbol: str
    kind: str = "param"
    line: str = ""
    call_expr: str = ""
    description: str = ""


def _safe_name(value: str, *, max_len: int = 96) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-") or "item"
    if len(safe) <= max_len:
        return safe
    return f"{safe[:max_len - 9]}-{hashlib.sha1(value.encode()).hexdigest()[:8]}"


def _node_id(source_file: str, function_name: str, symbol: str, depth: int) -> str:
    raw = f"{source_file}::{function_name}::{symbol}::{depth}"
    return "node_" + hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def _edge_id(run_id: str, function_name: str, src: str, dst: str, line: str) -> str:
    raw = f"{run_id}::{function_name}::{src}->{dst}@{line}::{uuid.uuid4().hex[:6]}"
    return "edge_" + hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:18]


def parse_taint_inputs(cfg: TaskConfig, fallback: Iterable[str] | None = None) -> list[TaintInput]:
    items: list[TaintInput] = []
    for detail in cfg.taint_details or []:
        if not isinstance(detail, dict):
            continue
        symbol = str(detail.get("name") or detail.get("taint") or detail.get("param") or detail.get("symbol") or "").strip()
        if not symbol:
            continue
        items.append(TaintInput(
            symbol=symbol,
            kind=str(detail.get("source_kind") or detail.get("kind") or "param").strip() or "param",
            line=str(detail.get("line") or detail.get("line_hint") or "").strip(),
            call_expr=str(detail.get("call_expr") or detail.get("call") or "").strip(),
            description=str(detail.get("description") or detail.get("reason") or "").strip(),
        ))
    for param in cfg.taint_params or []:
        symbol = str(param).strip()
        if symbol and all(x.symbol != symbol for x in items):
            items.append(TaintInput(symbol=symbol, kind="param"))
    for param in fallback or []:
        symbol = str(param).strip()
        if symbol and all(x.symbol != symbol for x in items):
            items.append(TaintInput(symbol=symbol, kind="param"))
    return items or [TaintInput(symbol="all", kind="unknown")]


def _extract_json_from_text(text: str, key: str | None = None) -> Any:
    candidates: list[str] = []
    for m in re.finditer(r"```(?:json)?\s*\n(.*?)\n\s*```", text, re.S):
        candidates.append(m.group(1))
    candidates.append(text)
    for raw in candidates:
        raw = raw.strip()
        for start_char, end_char in [("{", "}"), ("[", "]")]:
            start = raw.find(start_char)
            end = raw.rfind(end_char)
            if start >= 0 and end > start:
                try:
                    obj = json.loads(raw[start:end+1])
                    if key is None or (isinstance(obj, dict) and key in obj):
                        return obj
                except Exception:
                    pass
    return None


class DataflowVulnWorkflow:
    def __init__(
        self,
        *,
        cfg: TaskConfig,
        func_name: str,
        src_file: str,
        line_hint: str,
        taint_params: list[str],
        taint_ctx: str,
        task_id: str,
        out_dir: Path,
        dep: int,
        max_depth: int,
        graph_db_path: Path | None = None,
        vuln_output_root: Path | None = None,
        on_event: Callable[[SwarmEvent], None] | None = None,
        cancel_event: asyncio.Event | None = None,
    ):
        self.cfg = cfg
        self.func_name = func_name
        self.src_file = src_file
        self.line_hint = line_hint
        self.taint_inputs = parse_taint_inputs(cfg, taint_params)
        self.taint_params = [x.symbol for x in self.taint_inputs]
        self.taint_ctx = taint_ctx
        self.task_id = task_id
        self.out_dir = Path(out_dir)
        self.dep = dep
        self.max_depth = max_depth
        self.on_event = on_event or (lambda e: None)
        self.cancel_event = cancel_event
        self.run_id = f"{task_id}:{hashlib.sha1((src_file+'::'+func_name).encode()).hexdigest()[:12]}"
        self.store = VulnScanStore(graph_db_path or (self.out_dir / "vuln-scan.sqlite"))
        self.graph_json_path = self.store.db_path.with_name("vuln-scan-graph.json")
        self.vuln_root = Path(vuln_output_root) if vuln_output_root is not None else (self.out_dir / "output" / "vulnerabilities")
        self.vuln_root.mkdir(parents=True, exist_ok=True)

    def _emit(self, etype: str, **data: Any) -> None:
        try:
            self.on_event(SwarmEvent(type=etype, task_id=self.task_id, data=data))
        except Exception:
            pass

    def _cancelled(self) -> bool:
        return bool(self.cancel_event and self.cancel_event.is_set())

    def _seed_nodes(self) -> list[str]:
        node_ids: list[str] = []
        for item in self.taint_inputs:
            nid = _node_id(self.src_file, self.func_name, item.symbol, self.dep)
            node_ids.append(nid)
            self.store.upsert_taint_node(TaintSourceRecord(
                node_id=nid,
                source_file=self.src_file,
                function_name=self.func_name,
                taint_kind=item.kind,
                symbol=item.symbol,
                line=item.line,
                call_expr=item.call_expr,
                description=item.description,
                depth=self.dep,
            ))
        return node_ids

    def _write_design_doc(self) -> None:
        doc = self.out_dir / "vuln-scan-architecture.md"
        if doc.exists():
            return
        doc.write_text(
            "# 数据流漏洞挖掘架构\n\n"
            "## 输入\n文件名 + 函数名 + 污点信息(参数/返回值/调用参数/变量) + 源码目录。\n\n"
            "## SQLite 图数据库\n"
            "- `taint_nodes`: 污点源/中间污点对象/跨函数节点。\n"
            "- `taint_edges`: 单函数内每条污点传播边、校验/清洗/终止证据。\n"
            "- `followups`: 需要跟入的 callee 与污点参数。\n"
            "- `vulnerability_findings`: 每个漏洞独立记录并指向 output/vulnerabilities/<finding_id>。\n"
            "- `context_forks`: fork 出来的漏洞挖掘/跨函数分析上下文。\n\n"
            "## 终止规则\n"
            "1. 完整清洗或强校验后无危险使用。\n"
            "2. 污点仅参与日志/统计且不流入敏感 sink。\n"
            "3. 返回常量/错误码，原污点不再传播。\n"
            "4. 达到最大深度或遇到重复状态 `(file,function,taint-symbol)`。\n"
            "5. 无函数定义、标准库/宏展开不可跟入时记录 skipped。\n\n"
            "## 环路处理\n使用 `(source_file,function_name,taint_symbol,field_path)` 作为状态键；同一路径第二次出现标记 cycle，"
            "仅保留回边，不继续 fork。\n",
            encoding="utf-8",
        )

    async def _run_vuln_mining_fork(self, base_session: str, dataflow_text: str) -> list[VulnFindingRecord]:
        if self._cancelled() or not self.cfg.workers.agents:
            return []
        acfg = self.cfg.workers.agents[0]
        fork_session = self.out_dir / "sessions" / f"vuln-mining-{_safe_name(self.func_name)}.jsonl"
        try:
            if base_session and Path(base_session).exists():
                shutil.copyfile(base_session, fork_session)
        except OSError:
            pass
        fork_id = "fork_" + hashlib.sha1((self.run_id + str(fork_session) + "vuln").encode()).hexdigest()[:16]
        self.store.add_context_fork(
            fork_id=fork_id,
            run_id=self.run_id,
            purpose="vulnerability_mining",
            session_file=str(fork_session),
            node_id=_node_id(self.src_file, self.func_name, self.taint_params[0] if self.taint_params else "all", self.dep),
            status="running",
        )
        prompt = (
            f"# 阶段：漏洞挖掘 Fork\n\n"
            f"你正在一个从污点分析上下文复制出来的 fork session 中工作。\n"
            f"目标函数: `{self.src_file}::{self.func_name}`\n"
            f"污点: {', '.join(self.taint_params)}\n\n"
            f"基于下面的单函数污点传播结果，判断是否存在漏洞。\n"
            f"必须输出 JSON：{{\"findings\":[{{\"vuln_type\":...,\"severity\":...,\"title\":...,\"summary\":...,\"evidence\":...,\"exploitability\":...,\"confidence\":0.0}}]}}。\n\n"
            f"```markdown\n{dataflow_text[:30000]}\n```"
        )
        system_prompt = ""
        prompt_path = Path(__file__).resolve().parents[1] / "prompts" / "vuln-miners" / "default.md"
        try:
            system_prompt = prompt_path.read_text(encoding="utf-8")
        except OSError:
            pass
        output = await run_agent(
            prompt=prompt,
            model=acfg.model,
            tools=acfg.tools or self.cfg.workers.default_tools,
            cwd=str(self.out_dir),
            session_file=str(fork_session),
            system_prompt=system_prompt,
            cancel_event=self.cancel_event,
            run_timeout_seconds=self.cfg.agent_run_timeout_seconds,
            timeout_retry_enabled=self.cfg.agent_timeout_retry_enabled,
            timeout_max_retries=self.cfg.agent_timeout_max_retries,
            pi_max_retries=self.cfg.pi_max_retries,
            pi_retry_delay=self.cfg.pi_retry_delay,
            task_context={"task_id": self.task_id, "task_root": str(self.out_dir.parent), "task_run_root": str(self.out_dir)},
        )
        parsed = _extract_json_from_text(output.output, "findings") or {"findings": []}
        self.store.add_context_fork(
            fork_id=fork_id,
            run_id=self.run_id,
            purpose="vulnerability_mining",
            session_file=str(fork_session),
            node_id=_node_id(self.src_file, self.func_name, self.taint_params[0] if self.taint_params else "all", self.dep),
            status="completed" if not output.error else "error",
        )
        findings: list[VulnFindingRecord] = []
        for idx, item in enumerate(parsed.get("findings") or []):
            if not isinstance(item, dict):
                continue
            finding_id = f"vuln_{hashlib.sha1((self.run_id+str(idx)+json.dumps(item, ensure_ascii=False)).encode()).hexdigest()[:16]}"
            fdir = self.vuln_root / finding_id
            fdir.mkdir(parents=True, exist_ok=True)
            report = fdir / "vulnerability-report.md"
            taint_report = fdir / "taint-path-report.md"
            ctx_file = fdir / "context.jsonl"
            report.write_text(
                f"# {item.get('title') or finding_id}\n\n"
                f"- 类型: {item.get('vuln_type','unknown')}\n"
                f"- 严重性: {item.get('severity','unknown')}\n"
                f"- 置信度: {item.get('confidence',0)}\n\n"
                f"## 摘要\n{item.get('summary','')}\n\n"
                f"## 证据\n{item.get('evidence','')}\n\n"
                f"## 可利用性\n{item.get('exploitability','')}\n",
                encoding="utf-8",
            )
            taint_report.write_text(dataflow_text, encoding="utf-8")
            try:
                if fork_session.exists():
                    shutil.copyfile(fork_session, ctx_file)
            except OSError:
                ctx_file.write_text("", encoding="utf-8")
            rec = VulnFindingRecord(
                finding_id=finding_id,
                run_id=self.run_id,
                node_id=_node_id(self.src_file, self.func_name, self.taint_params[0] if self.taint_params else "all", self.dep),
                vuln_type=str(item.get("vuln_type") or "unknown"),
                severity=str(item.get("severity") or "unknown"),
                title=str(item.get("title") or finding_id),
                summary=str(item.get("summary") or ""),
                evidence=str(item.get("evidence") or ""),
                exploitability=str(item.get("exploitability") or ""),
                confidence=float(item.get("confidence") or 0),
                output_dir=str(fdir),
            )
            self.store.add_finding(rec)
            findings.append(rec)
        return findings

    def _record_edges_from_result(self, result: TaskResult, node_ids: list[str]) -> None:
        text = result.final_output or ""
        edges: list[TaintEdgeRecord] = []
        followups: list[FollowupRecord] = []
        # Best-effort structured parse: prompt asks for taint-graph.json; fallback to callee table parser.
        graph_path = next(self.out_dir.glob("workspace-worker-*/taint-graph.json"), None)
        graph = None
        if graph_path:
            try:
                graph = json.loads(graph_path.read_text(encoding="utf-8"))
            except Exception:
                graph = None
        if isinstance(graph, dict):
            validation_warnings = validate_taint_graph(graph)
            if validation_warnings:
                (self.out_dir / "taint-graph.validation.json").write_text(
                    json.dumps({"warnings": validation_warnings}, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
            for item in graph.get("edges") or []:
                if not isinstance(item, dict):
                    continue
                src = str(item.get("from") or item.get("from_symbol") or "").strip() or (self.taint_params[0] if self.taint_params else "unknown")
                dst = str(item.get("to") or item.get("to_symbol") or "").strip() or "unknown"
                edge = TaintEdgeRecord(
                    edge_id=_edge_id(self.run_id, self.func_name, src, dst, str(item.get("line") or "")),
                    run_id=self.run_id,
                    from_node_id=node_ids[0] if node_ids else "",
                    to_node_id=_node_id(self.src_file, self.func_name, dst, self.dep),
                    source_file=self.src_file,
                    function_name=self.func_name,
                    from_symbol=src,
                    to_symbol=dst,
                    line=str(item.get("line") or ""),
                    operation=str(item.get("operation") or ""),
                    evidence=str(item.get("evidence") or ""),
                    sanitizer=str(item.get("sanitizer") or ""),
                    sanitizer_effect=str(item.get("sanitizer_effect") or "none"),
                    validation=str(item.get("validation") or ""),
                    termination_reason=str(item.get("termination_reason") or ""),
                    confidence=float(item.get("confidence") or 0),
                )
                edges.append(edge)
        # Followups from tainted.list / parsed markdown are still consumed by Orchestrator; store them too.
        from .parsers import _parse_callees, _read_tainted_list
        callees = _read_tainted_list(str(self.out_dir)) or _parse_callees(text)
        for c in callees:
            eid = _edge_id(self.run_id, self.func_name, self.taint_params[0] if self.taint_params else "taint", c.function_name, c.line)
            edges.append(TaintEdgeRecord(
                edge_id=eid,
                run_id=self.run_id,
                from_node_id=node_ids[0] if node_ids else "",
                to_node_id=_node_id(c.file or self.src_file, c.function_name, c.tainted_params or "*", self.dep + 1),
                source_file=self.src_file,
                function_name=self.func_name,
                from_symbol=self.taint_params[0] if self.taint_params else "taint",
                to_symbol=c.tainted_params or "*",
                line=c.line,
                operation="call_arg",
                evidence=c.description,
            ))
            followups.append(FollowupRecord(
                followup_id="follow_" + hashlib.sha1((eid+c.function_name).encode()).hexdigest()[:16],
                edge_id=eid,
                parent_node_id=node_ids[0] if node_ids else "",
                callee_file=c.file or self.src_file,
                callee_function=c.function_name,
                callee_line=c.line,
                tainted_params_json=json.dumps([x.strip() for x in (c.tainted_params or "").split(',') if x.strip()], ensure_ascii=False),
                depth=self.dep + 1,
            ))
        self.store.add_taint_edges(edges)
        self.store.add_followups(followups)

    async def run(self) -> TaskResult:
        self._write_design_doc()
        self.store.start_run(self.run_id, self.task_id, self.src_file, self.func_name, self.cfg.cwd, self.cfg.model_dump())
        node_ids = self._seed_nodes()
        self._emit("vuln_scan_graph_start", function=self.func_name, source_file=self.src_file, taints=self.taint_params, depth=self.dep)

        legacy = PerTaintWorkflow(
            cfg=self.cfg,
            func_name=self.func_name,
            src_file=self.src_file,
            line_hint=self.line_hint,
            taint_params=self.taint_params,
            taint_ctx=self.taint_ctx,
            task_id=self.task_id,
            out_dir=self.out_dir,
            dep=self.dep,
            max_depth=self.max_depth,
            on_event=self.on_event,
            cancel_event=self.cancel_event,
        )
        result = await legacy.run()
        self._record_edges_from_result(result, node_ids)

        base_session = str(self.out_dir / "sessions" / "worker-0-base.jsonl")
        try:
            findings = await self._run_vuln_mining_fork(base_session, result.final_output or "")
            self._emit("vuln_scan_findings", function=self.func_name, count=len(findings), depth=self.dep)
        except Exception as exc:
            self._emit("vuln_scan_error", function=self.func_name, error=str(exc), depth=self.dep)

        graph_export = self.store.export_json()
        self.graph_json_path.write_text(json.dumps(graph_export, ensure_ascii=False, indent=2), encoding="utf-8")
        self.store.finish_run(self.run_id, result.status.value if hasattr(result.status, "value") else str(result.status))
        result.upstream_entry_metadata = dict(result.upstream_entry_metadata or {})
        summary = {
            "runs": len(graph_export.get("analysis_runs") or []),
            "nodes": len(graph_export.get("taint_nodes") or []),
            "edges": len(graph_export.get("taint_edges") or []),
            "followups": len(graph_export.get("followups") or []),
            "findings": len(graph_export.get("vulnerability_findings") or []),
        }
        result.vuln_summary = summary
        result.upstream_entry_metadata["vuln_scan"] = {
            "sqlite_path": str(self.store.db_path),
            "graph_json_path": str(self.graph_json_path),
            "vulnerabilities_dir": str(self.vuln_root),
        }
        return result
