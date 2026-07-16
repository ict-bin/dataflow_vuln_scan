# 完整模式污点分析设计

> 状态: 设计对齐中，未实现。
> 范围: **污点跟踪** = 单函数污点传播 DAG 分析 + 队列驱动的跨函数跟踪 + 去重 + 校验 + 剪枝 + 回传 + tracker 结果回填图。
> **不在本文档**: 漏洞挖掘（mine_vulns，独立文档）；专注模式（不管）。

## 0. 设计原则

1. **聚焦单函、单污点、独立会话**：一次分析 = 一个函数 × 一个污点签名，独立会话（不 fork 调用链上下文）。会话键 = `函数-taint`。
2. **校验只记录、不影响传播**：传播基于代码 def-use，不被调用链前置校验左右；校验供下游（挖掘）消费。
3. **传播条件 ≠ 污点校验**：边上的 `condition`（路径条件，选分支）与节点上的 `check`（sanitizer，对污点本身的约束）分开。
4. **clang 先出结构事实，LLM 用事实构建 DAG**：clang 解析函数 AST → 提取调用点/分支/校验等结构事实 → 注入 prompt → LLM 基于事实输出 DAG（condition/checks/sink_ref/param_taints 来自 clang，def-use 流/语义分类来自 LLM）。**不做 LLM 输出 → clang 匹配**（匹配本身不可靠）。
5. **去重 = (func_id, 归一化污点签名)**，不含前置校验；func_id 含类/命名空间+签名 → overload 不合并。
6. **队列驱动跨函数跟踪**：函数分析产出跟入项（callee/return/escape/indirect），去重后入分析队列，多线程并行消费。**编排器不递归遍历 DAG**。
7. **AI 为中心，无硬编码白名单**：低价值 callee / sanitizer 语义由 LLM 判断，脚本不维护名单。
8. **tracker 结果回填图**：escape/indirect tracker 解析出真实目标后，插入对应函数的 DAG（图被丰富）。
9. **挖掘时机 = per-function**：某函数某污点的外传链（所有 callee/return/escape 目标）全部已分析 → 该函数即可挖，不等全部 taint 跟踪完成。

## 1. 输入与独立会话

单次污点分析任务（一个分析队列项）：

| 字段 | 含义 |
|---|---|
| `func_id` | 函数标识 = `sha(file, name, signature)`（name 含类/命名空间限定，signature 含参数 → overload 区分） |
| `taint_signature` | 污点的归一化签名（`_norm_taint_sig`：去 `this->`/尾 `()`/lower） |
| `entry_line` | 污点传入时对应该文件行号（clang 填） |

- **独立会话**：每个 (func_id, taint_signature) 一个独立会话，**不 fork 调用链**。函数内传播自洽，不依赖 caller 上下文。
- 同函数多入口污点 → 多个独立分析项，各自去重、可并行。

## 2. 输出数据模型

### 2.1 传播 DAG（核心）

函数内污点传播是 **DAG**（非树）：分支后可在汇合点合并，merge 节点多 parent、全局唯一 id、只存一份。

```
TaintNode {
  id: int                  # 函数内唯一节点编号
  func_id: str
  taint_signature: str     # 本次分析的污点签名（归属一次分析）
  line: int                # 该节点对应代码行【clang 填】
  taint: str               # 该节点处的污点签名（归一化）
  parents: [int]           # 父节点 id（DAG；根=[]）
  children: [TaintEdge]    # 出边
  checks: [Check]          # 节点 sanitizer（见 2.3）【clang 提取，LLM 判语义】
  prune: PruneSignal?      # 剪枝信号（见 2.4）【可空】
  is_source: bool          # 污点源节点（无入口参数、函数内自生：返回值源/被动输入）【可空】
}

TaintEdge {
  to: int                  # 目标节点 id
  line: int                # 传播行号【clang 填】
  condition: [CondTerm]    # 路径条件（见 2.2）【clang 提取】
  taints: [str]            # 沿该边传播的污点签名列表（单污点时长度 1）
  kind: enum               # inside | callee | extern | container | return | source
  sink_ref: str?           # kind∈{callee,extern,container} 的流出目标引用【clang 校准】
  param_taints: [{param: str, taint: str}]?   # callee 边: callee 形参 ← caller 污点 映射【clang 提取实参】
  escape_subkind: str?     # extern/global | extern/field_alias | container
  carrier: str?            # 载体变量名（container/field_alias 常是 alloc 产物）
  escape_via: str?        # 逃逸调用名（仅记录）
}
```

### 2.2 传播条件 condition（边，路径条件）

**clang AST 精确提取**，不由 LLM 猜。clang 遍历 if/else/switch 分支栈 → 每个 CallExpr 的分支路径精确到代码行。

```
CondTerm =
  | Atom { left, op, right }                  # clang 提取的条件表达式
  | Compound { comb: "AND"|"OR", terms: [CondTerm] }   # clang 递归提取布尔结构
```

### 2.3 污点校验 check（节点，sanitizer）

**clang AST 提取 if-statement 中的条件**，**LLM 判语义**（是否是对污点本身的约束）。

```
Check { left: str, op: str, right: str }   # clang 提取条件表达式; LLM 判是否约束污点
```

- clang 提取所有 if-statement 的条件表达式 + 行号。
- LLM 判：哪些是对污点本身的约束（进 checks），哪些是纯路径条件（上边 condition）。
- **只记录、不影响传播**。

### 2.4 剪枝信号 PruneSignal（节点）

```
PruneSignal { reason: enum, detail: str }   # sanitized | low_value_callee | sink_recorded
```

- `sanitized`：污点被 sanitizer **清洗成安全**。→ **LLM 判**。路径守护/界值约束不是 sanitized。
- `low_value_callee`：该 callee 无安全跟踪价值。→ **LLM 语义判，无白名单**。
- `sink_recorded`：污点已到 sink 并落库。→ **编排器判**。

### 2.5 其他输出（保留）

- `description`：函数功能说明（回写函数库）。
- `self_contained`：本函数自身存在 sink → 立即挖；否则后序挖。
- `taint_failed`：分析全失败（retry 用尽），跳过下游。

## 3. 传播 DAG 的构建分工

### 3.1 两阶段：clang 先出事实 → LLM 用事实构建 DAG

**不用 compile_commands，用 libclang 语法解析**（`index.parse(args=..., options=PARSE_NONE)`，与 V2 相同——V2 已验证上百小时无 hang）。clang parse 失败 → 回退纯 LLM（不阻塞）。

#### 阶段 1: clang 提取结构事实

clang 解析函数体 AST → 提取：

| 事实 | clang 怎么提取 | 注入 prompt 什么 |
|---|---|---|
| **调用点表** | 遍历 CallExpr → 每个调用: callee 名、call_line、实参表达式列表、**分支路径**（if/else/switch 分支栈） | `callsites: [{callee, line, args, branch: "if(a->cmd==1) then"}]` |
| **分支结构** | 遍历 if/switch → 每个: condition 表达式文本、condition_line、then_range、else_range | `branches: [{line, condition, type:"if", then:[L1,L2], else:[L3,L4]}]` |
| **校验点** | 遍历 if-statement → 每个: condition 表达式、line、检查的变量名 | `checks: [{line, condition, checks_var}]` |
| **幽灵校验** | LLM 只能从 clang 给的调用点列表里选 callee | 不注入——LLM 不可能输出不存在的 callee |

#### 阶段 2: LLM 基于事实构建 DAG

prompt 注入：函数体 + clang 结构事实。

LLM 输出 DAG 的分工：

| DAG 字段 | 来源 | 说明 |
|---|---|---|
| `condition`（边） | **clang** | 用 clang 给的分支条件，不自己猜 |
| `checks`（节点） | **clang 提取 + LLM 判语义** | clang 给所有 if 条件；LLM 判哪些约束污点（进 checks）vs 纯路径条件（上 condition） |
| `sink_ref`（callee 边） | **clang** | 用 clang 给的 callee 名，不自己猜 |
| `param_taints` | **clang** | 用 clang 给的实参表达式映射 |
| `line` | **clang** | 精确 CallExpr 行号 |
| `kind` | **LLM** | 语义分类：inside/callee/extern/container/return/source |
| `taints`（def-use 流） | **LLM** | 哪些变量被污染、赋值链、派生 |
| `is_source` | **LLM** | 语义判：是否污点源（被动输入/返回值源） |
| `self_contained` | **LLM** | 语义判：本函数是否有自身 sink |
| `prune` | **LLM** | 语义判：sanitized/low_value_callee |
| `parents`/`children`/DAG 结构 | **LLM** | def-use 拓扑（哪些节点连哪些边） |

### 3.2 clang parse 失败时

libclang 不可用 / 文件解析失败 → 无结构事实 → prompt 不注入 clang 段 → LLM 回退到自己猜 condition/checks/sink_ref（和之前一样）。**不阻塞、不崩**。

### 3.3 tree-sitter 角色

tree-sitter 仍用于：
- **函数体提取**（function_extractor，已有）。
- **行号兜底**（clang parse 失败时，best-effort 填行号）。

## 4. 去重

- **key = (func_id, normalized_taint_signature)**。func_id 含类/命名空间限定 name + 完整参数 signature → overload 不合并。不含前置校验。
- **机制**：`processed_taints` PK = `(func_id, taint_signature)`；analyze 前 `try_reserve`（INSERT OR IGNORE，双检锁防并发重复分析）；analyze 失败 `delete` 占位。
- **回传污点**：return_taint 签名 ≠ 入口 → 不同 key → 不冲突，自然触发新分析（见 §6）。

## 5. 校验只记录

- 节点 `check` + 边 `condition` 都是 analyze 输出（来自 clang + LLM 语义判），落库供下游（挖掘）消费。
- analyze **不读前置校验链**：`_build_prompt` 不渲染前置校验链。
- 校验沿调用链累积（callee 的 ctx 带 caller 的 check）仅供挖掘上下文，**不进 dedup key**、**不影响传播**。

## 6. 回传分析（return_taint）

- **保留**。callee 在 `kind=return` 边返回的新污点 → 产出一个**回传跟入项** `(caller_func_id, return_taint_sig)` 入分析队列（见 §9），触发 caller 的新分析。
- 回传污点签名 ≠ 入口 → 去重不冲突。
- escape-source 逻辑保留：回传污点 caller 本函数已持有（escape 源头场景）→ 跳过，避免冗余循环。

## 7. 单污点独立 + 并行

- `taint_params` 单污点。同函数多入口污点 → 多个独立分析项。
- 并行：多线程消费分析队列（见 §9），不同 (func, taint) 互不影响；同 (func, taint) 由 `try_reserve` 双检锁保证只分析一次。

## 8. DAG 落库（独立表，旧表废弃）

- **新表**（按一次分析 = (func_id, taint_signature) 归属）：
  - `taint_dag_nodes`：`(func_id, taint_signature, node_id, line, taint, parents_json, checks_json, prune_json)`，PK `(func_id, taint_signature, node_id)`。
  - `taint_dag_edges`：`(func_id, taint_signature, from_node, to_node, line, condition_json, taint, kind, sink_ref)`，PK `(func_id, taint_signature, from_node, to_node, kind)`。
- **旧表废弃**：`taints` / `propagations` 表移除（DAG 是超集）。`processed_taints` 保留（去重锚点）。
- description/self_contained/taint_failed 存 `taint_dag_meta`（一行/分析）。

## 9. 队列驱动的跨函数跟踪（编排重设计）

**不再递归 DFS**。改为**生产者-消费者工作队列**，本质是对跨函数污点传播图的 BFS：每个 (func, taint) 只分析一次，其 DAG 为权威数据，下游跟入项从 DAG 重放。

### 9.1 跟入项（work item，轻量引用）

DAG 是权威数据，跟入项只带**目标 + 溯源引用**，line/condition 等留在 DAG 里直接引用（D-5）。

- `callee`：`(callee_func_id, callee_taint_sig, origin_func, origin_node, origin_edge)` → 跟入 callee 分析该污点。
  - **taint_sig = callee 形参名归一化**（D-1）。
  - **多污点参数拆项**（D-2）。
- `return_taint`：`(caller_func_id, return_taint_sig, callee_func, origin_edge)` → 回传重分析 caller。
- `escape_track`：`(origin_func, origin_edge)` → 触发 escape tracker。
- `indirect_track`：`(origin_func, origin_edge)` → 触发 indirect tracker。

### 9.2 消费逻辑（核心：分析一次 + 重放下游）

队列项 `(func, taint)` 被拉取后：

1. `find_processed_taint(func, taint)`：
   - **未分析** → `try_reserve` 成功 → analyze（clang 事实 + LLM）→ 存 DAG → 从**新 DAG** 重放下游项入队。
   - **已分析** → **不重分析** → 加载已存 DAG → 从**已存 DAG** 重放下游项入队。
2. 重放的下游项 = 该 DAG 的 `callee` 边 / `return` 边 / `extern`/`container` 边（→escape_track）/ 间接 `callee` 边（→indirect_track）。
3. 下游项入队后各自再走 9.2（BFS 传播），每项归结为某 (func, taint) → `try_reserve` 兜底去重。

### 9.3 tracker 结果经中继点接回图

- **escape tracker**：extern/container 边的目标节点是**中继点**。tracker 找到读者 R 后，从中继点节点出一条 `kind=callee` 边到 R + 产出 `callee` 跟入项入队。
- **indirect tracker**：间接 callee 边 sink_ref=指针表达式 → tracker 解析真实函数 F → 回填 sink_ref=F + 产出 `(F, taint_sig)` 队列项。

### 9.4 condition 不跨函数（D-4）

condition 只记录在 caller DAG 边上，供挖掘按路径条件判漏洞；**不进 callee 的 analyze**、不进队列项。

### 9.5 并行与终止

- **并行**：多线程消费队列；同 (func, taint) 由 `try_reserve` 双检锁保证只 analyze 一次。
- **终止**：**队列空 + 线程池均无在途任务**（所有 worker idle）= 污点跟踪完成。

## 10. 挖掘启动时机（per-function）

**不等全部 taint 跟踪完成**。某函数某污点 (func_id, taint_sig) 满足以下条件即可挖：
- 该函数的 DAG 已存（分析完成）。
- 该函数的**所有外传链目标**（callee 边的 callee_func_id + return 边的 caller_func_id）的 DAG **均已分析完成**（或无外传链）。

满足后立即对该 (func, taint) 启动挖掘（正向建链 + D1-D4 + findings），可与 taint 跟踪并行。

## 11. 行号策略

- **clang parse 成功** → clang 精确填 call_line / 节点行。
- **clang parse 失败** → tree-sitter best-effort 填行号（变量名/赋值目标/callee 名匹配 AST 节点）。
- 全函数都无法定位 → 标记可疑，不丢。

## 12. 测试库（上线门禁）

- 构造最小 C/C++ 样例 + 预期 DAG（golden = 人工校验首次产出）。
- 上线前必须全过。
- 覆盖：赋值链、分支汇合、复合条件、sanitizer、callee 透传、多污点参数、extern/container 逃逸、return 回传、间接调用、escape-source 冗余、低价值剪枝、overload、重放拼接。

## 13. 与当前的差异（迁移要点）

| 当前 | 设计 | 迁移 |
|---|---|---|
| 递归 DFS | 队列驱动工作项 + 多线程消费 | 重写编排为队列 |
| `propagations[]`+`taints[]` 扁平 | DAG 节点+边 | 新模型+新表 |
| LLM 输出 condition（不可靠） | **clang 先出事实 → LLM 用事实构建** | 新两阶段构建 |
| tree-sitter 填行号 | **clang 精确填行号**（tree-sitter 兜底） | 升级 line_filler |
| `validations` 混在 propagation | 拆 condition(边)/check(节点) | 拆分 |
| 校验影响传播 + 进 dedup | 只记录 + 不影响 + 不进 dedup | 去 pre_val |
| fork 会话链 | 独立会话（不 fork） | 去 fork/copyfile |
| `taint_params.names` list | 单污点 | 拆入口 |
| mining 在 analyze 同流程 | mining 拆独立文档 | 本文不管 |
| 挖掘等全部 tracking 完成 | **per-function: 外传链全分析即挖** | 新触发逻辑 |
| dedup `(func_id, taint_sig, pre_val)` | `(func_id, taint_sig)` | 去 pre_val |
| run_agent 缺 task_pi_dir | 补齐 task_pi_dir/task_root/task_run_root | 已修 |

## 14. 已确认决策

1. description / self_contained / taint_failed **保留**。✅
2. **挖掘独立文档**，本文只管污点跟踪。✅
3. DAG **独立表**（nodes+edges），旧表废弃。✅
4. **队列驱动**（不递归遍历 DAG）。✅
5. tracker 结果**回填图**。✅
6. **clang 先出事实 → LLM 用事实构建 DAG**（不做 LLM→clang 匹配）。✅
7. **不管专注模式**。✅
8. 每函数**独立会话**。✅
9. **测试库**上线门禁。✅
10. overload 不合并。✅
11. 复合条件独立记录（CondTerm 递归）。✅
12. 队列项 taint_sig = callee 形参名归一化（D-1）。✅
13. 多污点参数拆 N 项（D-2）。✅
14. condition 不跨函数（D-4）。✅
15. DAG 为权威数据（D-5）。✅
16. 终止 = 队列空 + 线程池无在途任务（D-6）。✅
17. **挖掘时机 = per-function**（外传链全分析即挖，不等全部 tracking 完成）。✅
18. **clang 不复用 V2**（自行设计 dagflow clang_annotator）。✅
19. **run_agent 补齐 task_pi_dir/task_root/task_run_root + fork_purpose 用 V2 标准值**。✅
