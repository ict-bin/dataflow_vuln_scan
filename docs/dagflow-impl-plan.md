# dagflow 实现计划

> 新管线（DAG 污点跟踪 + 正向建链挖掘）独立实现。独立包、子功能独立文件、任务级开关、不动现有完整/自主模式代码、可快速删旧换新。

## 1. 开关（任务级）

`task_config_json.feature_flags.dagflow_mode`（沿用现有 feature_flags 机制）。

分流点 `app/service/task_service.py` ~L2256：
```python
if cfg.feature_flags.get("dagflow_mode"):
    from app.dagflow.pipeline import DagflowPipeline
    orch = DagflowPipeline(config=cfg, on_event=on_event, task_id=task_id)
elif cfg.feature_flags.get("autonomous_mode"):
    from app.dataflow_v2.autonomous import AutonomousRunner
    orch = AutonomousRunner(...)
else:
    orch = Orchestrator(...)   # 现有完整模式, 不动
```
- dagflow_mode 关 → 现有完整/自主模式原样跑（零影响）。
- dagflow_mode 开 → 走新管线。
- 上线替换：删 `dataflow_v2/` 完整模式代码 + 删 elif 分支，dagflow 变默认。

## 2. 包布局 `app/dagflow/`（独立，每子功能一文件）

| 文件 | 职责 | 依赖 |
|---|---|---|
| `models.py` | 纯数据模型: TaintNode/TaintEdge/CondTerm/Check/PruneSignal/WorkItem/Finding | 无 |
| `dag_store.py` | DAG 存储: taint_dag_nodes/edges + processed_taints 表 | models |
| `dedup.py` | try_reserve/find/delete processed_taint (func_id, taint_sig) 双检锁 | dag_store |
| `taint_analyzer.py` | LLM analyze 产 DAG(无行号) + JSON 解析 | models, runner |
| `line_filler.py` | tree-sitter 据语义锚点填行号 | function_extractor(共享) |
| `work_queue.py` | BFS 工作队列: 项/去重/并行消费/终止 | dedup, dag_store |
| `orchestrator.py` | 队列驱动 taint 跟踪: 产 DAG + 发跟入项 + 重放拼接 | work_queue, taint_analyzer, line_filler |
| `escape_tracker.py` | escape 经中继点接回(LLM+v2_db 找读者) | dag_store, models |
| `indirect_tracker.py` | 间接调用解析真实函数 | dag_store, models |
| `trackers.py` | escape + indirect 统一调度入口 | escape_tracker, indirect_tracker |
| `dag_tools.py` | 挖掘 agent 的 DAG 查询工具(dag_get/callee_effect/walk_children/get_func_source/dag_callers) | dag_store |
| `chain_builder.py` | 正向建链: 从入口按序拼 callee 效应 | dag_tools, models |
| `mining_agent.py` | 挖掘 LLM agent: 建链 + D1-D4 + findings | chain_builder, dag_tools, runner |
| `trigger.py` | 挖掘触发: 传出点就绪判定 | dag_store |
| `finding_store.py` | findings 存储 + 去重(finding_id + 跨段) | vuln_store(共享, 兼容上报) |
| `pipeline.py` | 入口: taint 跟踪阶段 → 挖掘阶段; 同 Orchestrator 接口(execute_recursive) | 全部 |

## 3. 共享工具（复用，非模式逻辑）

- `function_extractor`（tree-sitter 函数体/AST）— line_filler + 源码取用。
- `run_agent`（LLM runner）— taint_analyzer + mining_agent。
- `v2_db`（宏/符号/callee 查询）— mining_agent 工具。
- `VulnScanStore`/`VulnFindingRecord`（上报层）— finding_store 写兼容格式（vuln-scan.sqlite + intake + MySQL count-sync 复用）。
- `TaskConfig`/config models — 复用。

**不碰**: `dataflow_v2/orchestrator.py`(DfsOrchestrator) / `analysis.py` / `store.py`(DataflowStore) / `trackers.py`(V2) / `mine_vulns` / `autonomous.py`。

## 4. 独立存储（不与 V2 表混）

- `taint_dag_nodes` / `taint_dag_edges` / `dag_processed_taints`（新表，独立于 V2 functions/taints/propagations/processed_taints）。
- findings → 复用 `vuln-scan.sqlite` 的 `vulnerability_findings` 表（兼容上报）。
- run 目录: `run/dagflow/`（独立于 `run/dataflow-v2/`）。

## 5. 实现阶段

- **P1 脚手架**: models + 包 + 开关分支 + pipeline stub（同接口，空跑）。验证开关不影响现有。
- **P2 数据模型+存储**: dag_store + dedup（DAG 表 + processed_taint 双检锁）。
- **P3 taint 分析器**: taint_analyzer（LLM 出 DAG 无行号）+ line_filler（tree-sitter 填行号）。
- **P4 队列编排**: work_queue + orchestrator（产 DAG + 发项 + 重放）。
- **P5 tracker**: escape（中继）+ indirect。
- **P6 挖掘**: dag_tools + chain_builder + mining_agent + trigger + finding_store。
- **P7 测试库回归**: 跑 27 例 golden 比对。
- 每阶段用测试库回归，dagflow_mode 默认关，验证不影响现有。
