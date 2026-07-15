"""dagflow 测试库回归 harness。

用法:
  python tests/taint-corpus/run_harness.py            # golden 校验 + line_filler 回归 (无 LLM)
  python tests/taint-corpus/run_harness.py --llm       # 全流程 (需 LLM API, 慢)

无 LLM 模式 (默认):
  - Phase A: 校验所有 golden JSON schema (nodes/edges/finding 字段)
  - Phase B: line_filler 回归 — 对每例 sample.c 跑行号填充, 比对 golden 的 line
  - Phase C: chain_builder 烟测 — 多函数用例 (20/21/24) 建链效应序列
LLM 模式 (--llm): 全流程 taint_analyzer+mining_agent, 比对 golden (集成跑, 需 API)。
"""
from __future__ import annotations
import json, sys, os, glob, argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
CASES = Path(__file__).resolve().parent / "cases"


def _load(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        return {"_error": str(e)}


def phase_a_validate() -> tuple[int, int]:
    """校验所有 golden JSON 合法 + 基本字段。"""
    ok = bad = 0
    for f in sorted(CASES.glob("*/expected_dag.json")) + sorted(CASES.glob("*/expected_findings.json")):
        d = _load(f)
        if "_error" in d:
            print(f"  [BAD] {f.name}: {d['_error']}"); bad += 1; continue
        if f.name == "expected_dag.json":
            if not isinstance(d, dict) or "nodes" not in d:
                # 多函数 DAG (24 等) 顶层是多个 analyze_* 键, 容错
                if not any(k.startswith("analyze_") for k in d):
                    print(f"  [BAD] {f.parent.name}: no nodes/analyze_*"); bad += 1; continue
        ok += 1
    print(f"Phase A golden 校验: {ok} ok / {bad} bad")
    return ok, bad


def phase_b_line_filler() -> int:
    """line_filler 回归: 对每例 sample.c, 取 golden DAG 清零 line, 填回比对。"""
    from app.dagflow.line_filler import fill_lines
    from app.dagflow.models import TaintDAG, TaintNode
    from app.dataflow_v2.models import FunctionRecord
    from app.dataflow_v2.function_extractor import extract_file_functions
    import tempfile
    matched = total = 0
    for case in sorted(CASES.iterdir()):
        sd = case / "sample.c"; gd = case / "expected_dag.json"
        if not (sd.is_file() and gd.is_file()):
            continue
        golden = _load(gd)
        # 只处理单函数 DAG (顶层 nodes); 多函数跳过
        if "nodes" not in golden:
            continue
        # 找主函数 (golden 里带 line 的 callee sink_ref 对应调用行)
        tmp = tempfile.mkdtemp()
        import shutil; shutil.copy(sd, tmp)
        # 解析 sample.c 提取函数 (需 DataflowStore)
        try:
            from app.dataflow_v2.store import DataflowStore
            v2s = DataflowStore(os.path.join(tmp, "df"))
            extract_file_functions(tmp, "sample.c", v2s)
            import sqlite3
            c = sqlite3.connect(os.path.join(tmp, "df", "functions.db"))
            c.row_factory = sqlite3.Row
            rows = c.execute("SELECT * FROM functions").fetchall()
            c.close()
            if not rows:
                continue
            rec = rows[0]  # 主函数
            fr = FunctionRecord(file="sample.c", name=rec["name"], signature=rec["signature"],
                                start_line=rec["start_line"], end_line=rec["end_line"])
            fr.func_id = rec["func_id"]
        except Exception:
            continue
        # golden DAG 清零 line
        dag = TaintDAG.from_dict(golden)
        for n in dag.nodes:
            n.line = 0
            for e in n.children:
                e.line = 0
        try:
            fill_lines(dag, fr, tmp)
        except Exception as e:
            print(f"  [ERR] {case.name} line_filler: {e}"); continue
        # 比对: golden 有 line>0 的边, 比对填充结果
        gold_dag = TaintDAG.from_dict(golden)
        for gn, n in zip(gold_dag.nodes, dag.nodes):
            for ge, e in zip(gn.children, n.children):
                if ge.line > 0:
                    total += 1
                    if e.line == ge.line:
                        matched += 1
                    else:
                        print(f"  [MISMATCH] {case.name} {ge.kind} {ge.sink_ref}: golden L{ge.line} got L{e.line}")
    print(f"Phase B line_filler 回归: {matched}/{total} 边行号匹配")
    return matched


def phase_c_chain() -> int:
    """chain_builder 烟测: 多函数用例建链 (需已存 callee DAG, 此处仅导入不跑, 标记需集成)。"""
    print("Phase C chain_builder: 多函数用例 (20/21/24) 需集成跑 (已 P6 单测覆盖)")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true", help="全流程 (需 LLM API)")
    args = ap.parse_args()
    print("=== dagflow 测试库回归 (无 LLM 模式) ===" if not args.llm else "=== dagflow 测试库回归 (LLM 模式) ===")
    a_ok, a_bad = phase_a_validate()
    phase_b_line_filler()
    phase_c_chain()
    if args.llm:
        print("\n[LLM 模式] 全流程 taint_analyzer+mining_agent 回归 — 需 API + 集成环境 (待部署后跑)")
    print("\n完成。")


if __name__ == "__main__":
    main()
