# dataflow_vuln_scan 架构重构设计

## 目标

`dataflow_vuln_scan` 不再只是复用数据流分析能力，而是按以下流程执行：

1. 单函数内污点传播精细分析。
2. 将污点节点、边、清洗/校验/终止信息写入 task-local SQLite 图数据库。
3. 从当前上下文 fork 一份漏洞挖掘上下文，判断当前函数内路径是否形成漏洞。
4. 根据 followup callee 继续跨函数跟入；多个跟入点使用独立上下文并由 worker 队列按 POD 槽位调度。
5. 漏洞按 finding 独立输出目录归档。

## 输入模型

任务输入包括：

- `source_file`: 文件名或相对源码路径。
- `function_name`: 目标函数名。
- `source_root_path`/`input_path`: 源码目录。
- `taint_params`: 函数入参型污点。
- `taint_details`: 更通用的污点描述，可表示：
  - 函数入参；
  - 某行函数调用返回值；
  - 某行函数调用参数；
  - 局部变量/字段/全局对象。

## 污点源自动识别（depth=0 预阶段，常开）

任务**允许不提供任何污点信息**。当 `taint_details` 无有效 symbol 且 `taint_params` 为空或仅为 `all` 哨兵时，系统会在根函数（depth=0）进入 BFS 污点追踪**之前**，先自动识别污点源：

1. 用 `extract_func` 提取根函数**完整函数体**（带绝对行号）。
2. 拉起**一个独立系统提示词的 pi agent**（`prompts/taint-source-id/default.md`），把完整函数体嵌入 prompt，**单轮会话、无 Judge**。该 agent 的模型/工具/思考等级/重试与 Worker 完全一致（复用 `workers.agents[0]`），仅系统提示词不同。
3. agent 只判断「哪些数据来自外部 / 不可信来源」，不做传播追踪、不做漏洞分析、不写任何文件，输出严格 JSON：

   ```json
   {
     "function": "foo",
     "source_file": "a.c",
     "no_external_input": false,
     "taints": [
       {"symbol": "aMessage", "kind": "param", "line": "L228", "reason": "外部网络报文"}
     ]
   }
   ```

4. 服务端解析并过滤（去 `&` 前缀、去 `all`、去伪符号 `v\d+`、去重、`_is_likely_external_taint_symbol`），**回填到根任务输入** `cfg.taint_params` / `cfg.taint_details`，随后接续既有 BFS 污点追踪流程。

特性：

- **常开、无配置项**：缺省即生效，不暴露任何开关。
- **只作用于 depth=0 根函数**；子函数（callee）的污点仍由调用点 P0/P1/P2 分流计算，不走此预阶段。
- **失败安全**：函数体提取失败 / agent 出错 / 识别为空 → 静默退回 `all`（分析全函数），不影响任务成败。
- 实现：`app/taint_source_identifier.py`（`needs_taint_autodetect` + `autodetect_taint_sources`），由 `app/orchestrator.py::execute_recursive` 根分支调用。

### 产物与可观测

- Session 归档：`run/sessions/d00-taint-source-id.jsonl`（可回放）。
- 事件流：`taint_autodetect_start` → `taint_autodetect_done`（含识别出的 `taints` / `count`）或 `taint_autodetect_empty`（含 `no_external_input` / `error`）。
- token 计入任务最终 `total_tokens`。

## SQLite 图数据库

每个任务在 `run/vuln-scan.sqlite` 中维护完整树/图。

### `analysis_runs`

记录一次函数级分析运行：task、根文件、根函数、源码根目录、状态、配置快照。

### `taint_nodes`

记录污点源和中间污点载体：

- `taint_kind`: `param | return_value | call_argument | local | field | global | unknown`
- `symbol`: 污点变量/字段/表达式。
- `line`: 来源行。
- `parent_node_id`: 跨函数父节点。
- `depth`: 递归深度。
- `context_session`: 产生该节点的上下文文件。

### `taint_edges`

记录单函数内每条传播边：

- `from_symbol` -> `to_symbol`
- `operation`: assignment/call_arg/return/field/container/condition/sink/terminate/validation/sanitizer
- `evidence`: 带行号源码证据。
- `sanitizer`: 清洗/校验函数或表达式。
- `sanitizer_effect`: `none | partial | complete | unknown`
- `validation`: 边界、长度、权限、类型、状态机等校验。
- `termination_reason`: 如果终止，必须记录原因。

### `followups`

记录下一步需要跟入的函数以及对应污点参数。状态支持：

- pending/queued/running/completed/skipped/cycle/depth_limit

### `vulnerability_findings`

每个漏洞独立记录，并指向：

```text
output/vulnerabilities/<finding_id>/
  taint-path-report.md
  context.jsonl
  vulnerability-report.md
```

### `context_forks`

记录 fork 的上下文：

- `purpose=vulnerability_mining`: 当前函数漏洞判断 fork。
- 后续可扩展 `purpose=followup_analysis`。

## Fork 策略

### 漏洞挖掘 fork

当前函数污点分析完成后，复制 base session 为漏洞挖掘 session，仅判断当前函数内是否存在漏洞，不继续递归。

### Followup fork

当前函数有多个跟入点时：

- 第一个跟入点复用主递归队列上下文。
- 第 2..N 个跟入点视为独立 fork，上下文由 BFS worker 池排队执行。
- 实际进程并发由现有 worker slot / lease / `callee_concurrency` 控制，避免超过 POD agent 槽位。

## 终止规则

污点传播可终止但必须写入图数据库：

1. 完整清洗/强校验后，后续只使用安全值。
2. 污点只进入日志/统计/调试输出，不影响敏感操作。
3. 函数返回常量/错误码，污点未写入输出参数、全局对象、堆对象。
4. 达到最大深度。
5. `(source_file,function_name,taint_symbol,field_path)` 状态重复，标记 cycle/back-edge。
6. 无可解析函数定义或标准库/宏无法跟入，标记 skipped/unknown，不直接判定安全。

## 环路与回合路径

状态键：

```text
source_file :: function_name :: taint_symbol :: field_path
```

策略：

- 首次出现：正常分析。
- 第二次出现：记录回边，允许保守摘要，但不再无限展开。
- 达到 `max_trace_depth`：记录 depth_limit followup。

## API

新增主接口：

```text
GET /api/app/dataflow-vuln-scan/tasks/{task_id}/graph-view
```

兼容投影接口：

```text
GET /api/app/dataflow-vuln-scan/tasks/{task_id}/vuln-graph
GET /api/app/dataflow-vuln-scan/tasks/{task_id}/vuln-findings
```

## 阶段提示词与 Skill

提示词：

```text
prompts/entry-screen/default.md
prompts/taint-graph/default.md
prompts/vuln-miners/default.md
prompts/followups/default.md
```

Skills：

```text
skills/write-taint-graph/SKILL.md
skills/mine-dataflow-vulnerability/SKILL.md
```
