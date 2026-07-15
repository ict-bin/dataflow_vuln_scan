# 完整模式污点分析设计

> 状态: 设计对齐中，未实现。
> 范围: **污点跟踪** = 单函数污点传播 DAG 分析 + 队列驱动的跨函数跟踪 + 去重 + 校验 + 剪枝 + 回传 + tracker 结果回填图。
> **不在本文档**: 漏洞挖掘（mine_vulns，独立文档）；专注模式（不管）。

## 0. 设计原则

1. **聚焦单函、单污点、独立会话**：一次分析 = 一个函数 × 一个污点签名，独立会话（不 fork 调用链上下文）。会话键 = `函数-taint`。
2. **校验只记录、不影响传播**：传播基于代码 def-use，不被调用链前置校验左右；校验供下游（挖掘）消费。
3. **传播条件 ≠ 污点校验**：边上的 `condition`（路径条件，选分支）与节点上的 `check`（sanitizer，对污点本身的约束）分开。
4. **结构事实由脚本保证**：行号等结构性事实由脚本（tree-sitter）填入，LLM 不输出行号、不碰行号可靠性。
5. **去重 = (func_id, 归一化污点签名)**，不含前置校验；func_id 含类/命名空间+签名 → overload 不合并。
6. **队列驱动跨函数跟踪**：函数分析产出跟入项（callee/return/escape/indirect），去重后入分析队列，多线程并行消费。**编排器不递归遍历 DAG**。
7. **AI 为中心，无硬编码白名单**：低价值 callee / sanitizer 由 LLM 语义判断，脚本不维护名单。
8. **tracker 结果回填图**：escape/indirect tracker 解析出真实目标后，插入对应函数的 DAG（图被丰富）。

## 1. 输入与独立会话

单次污点分析任务（一个分析队列项）：

| 字段 | 含义 |
|---|---|
| `func_id` | 函数标识 = `sha(file, name, signature)`（name 含类/命名空间限定，signature 含参数 → overload 区分） |
| `taint_signature` | 污点的归一化签名（`_norm_taint_sig`：去 `this->`/尾 `()`/lower） |
| `entry_line` | 污点传入时对应该文件行号（脚本填） |

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
  line: int                # 该节点对应代码行【脚本填，非 LLM】
  taint: str               # 该节点处的污点签名（归一化）
  parents: [int]           # 父节点 id（DAG；根=[]）
  children: [TaintEdge]    # 出边
  checks: [Check]          # 节点 sanitizer（见 2.3）【可空】
  prune: PruneSignal?      # 剪枝信号（见 2.4）【可空】
  is_source: bool          # 污点源节点（无入口参数、函数内自生：返回值源/被动输入）【可空】
}

TaintEdge {
  to: int                  # 目标节点 id
  line: int                # 传播行号【脚本填】
  condition: [CondTerm]    # 路径条件（见 2.2）【可空=无条件】
  taints: [str]            # 沿该边传播的污点签名列表（单污点时长度 1）
  kind: enum               # inside | callee | extern | container | return | source
  sink_ref: str?           # kind∈{callee,extern,container} 的流出目标引用
  param_taints: [{param: str, taint: str}]?   # callee 边: callee 形参 ← caller 污点 映射
  escape_subkind: str?     # extern/global | extern/field_alias | container （extern 细分）
  carrier: str?            # 载体变量名（container/field_alias 常是 alloc 产物）
  escape_via: str?        # 逃逸调用名（仅记录，如 enqueue/list_add）
}
```

`kind`：
- `inside`：函数内赋值/数据流（a=t）。
- `callee`：传入直接调用（handle(a)）；间接调用 sink_ref=指针表达式（待 tracker 解析回填为限定名）。
- `extern`：流入外部变量/类成员变量（escape_subkind=global/field_alias）。
- `container`：流入队列/堆内存容器（escape_subkind=container, carrier=载体, escape_via=插入调用）。
- `return`：经 return 流出（→ return_taint，见 §6）。
- `source`：污点源边——函数内自生污点（无入口参数）：返回值源（`t=getenv()`）或被动输入（`read(fd,buf)` 写 out-param）。

> **多污点参数**（GAP-1 A）：一条 callee 调用传多个污点参数时，`taints:list` + `param_taints` 映射，一条边一调用；followup 按**每个被污 callee 形参**拆项独立分析。
> **callee 限定名**（GAP-4）：`sink_ref` 必须是限定名（`A::handle`，含类/命名空间），LLM 输出 + tree-sitter 从调用点对象类型补全。
> **escape 中继点**（GAP-6）：extern/container 边的目标节点是**中继点**（g_cache/head）；tracker 找到读者 R 后，从中继点节点出一条 `kind=callee` 边到 R（读者经中继接回传播路径），并产出 `(R, taint)` 队列项。escape 节点是 DAG 一等节点，不是死路。

### 2.2 传播条件 condition（边，路径条件）

取该分支需满足的条件，**不清洗污点**。复合条件（`&&`/`||`）**独立记录**，保留布尔结构，不拍平、不拆边。

```
CondTerm =
  | Atom { left, op, right }                  # {a->cmd, ==, 1}
  | Compound { comb: "AND"|"OR", terms: [CondTerm] }   # 递归保留结构
```

- `if(a->cmd == 1) handle(a)` → 边 condition=`[Atom{a->cmd,==,1}]`。
- `if(a->cmd==1 && b->flag) proc(a)` → `[Compound{AND,[Atom{a->cmd,==,1}, Atom{b->flag,!=,0}]}]`。
- 互斥分支（if/else/switch 不同 arm）由不同边表达，各带自己 condition；互斥性由分支结构定（同 if 的 then/else 互斥）。

### 2.3 污点校验 check（节点，sanitizer）

节点上记录**对污点本身的约束**（清洗/约束/终止），**不**记录纯路径选择。

```
Check { left: str, op: str, right: str }   # left 必须是该污点或其字段
```

- 进 check 判据：**只对污点本身做约束**的才算。
  - `if(t == NULL) return` → check `{t,==,NULL}`（终止）✅
  - `if(msg->length < 100)` → check `{msg->length,<,100}`（约束）✅
  - `if(a->cmd == 1) handle(a)` → **不进 check**（a->cmd 非对污点 a 本身的约束，是路径条件，上边）。
- **只记录、不影响传播**：check 不抑制 def-use 流；供下游（挖掘）判断。

### 2.4 剪枝信号 PruneSignal（节点）

```
PruneSignal { reason: enum, detail: str }   # sanitized | low_value_callee | sink_recorded
```

- `sanitized`：污点被 sanitizer **清洗成安全**（t 不再是污点，如 `t=cleanse(t)`/escape/截断后无危险）。→ **LLM 判**。**仅指清洗**——路径守护/界值约束（`if(t==NULL)return`/`if(len>100)return`）不是 sanitized：t 仍为污点，只是受限路径才传播，走 check + condition（不 prune）。
- `low_value_callee`：该 callee 无安全跟踪价值（debug/print/log）。→ **LLM 语义判，无白名单**。
- `sink_recorded`：污点已到 sink（extern/container/return）并落库。→ **不由 LLM 判**，编排器在 kind∈{extern,container,return} 边落库时定，不再跟入该边本身。但 extern/container 边产 `escape_track` 项——tracker 解析读者后经**中继点**接回传播路径（见 §9.3），即“记录 sink + tracker 派生读者跟入”并存。

### 2.5 其他输出（保留）

- `description`：函数功能说明（回写函数库）。
- `self_contained`：本函数**自身存在 sink**（memcpy/strcpy/system/free-use 等本函数即触发点）→ 立即挖；否则后序挖。**挖掘时序由它定，挖掘实现见独立文档**。
- `taint_failed`：分析全失败（retry 用尽），跳过下游。

## 3. 传播 DAG 的构建分工

**无法编译**（无 compile_commands）→ clang AST 不可用。**LLM 输出拓扑与语义，脚本（tree-sitter）填结构事实**。

- **LLM 输出**（读 tree-sitter 提取的函数体，语义分析后输出，**不含行号**）：
  - 节点：污点在各 def/参数点的实例（id + taint + 语义锚点，如变量名/赋值目标，供脚本定位行）。
  - 边：def-use 流（赋值/实参/返回），含 kind/condition/taint/sink_ref（**无 line**）。
  - 分支与汇合：if/switch 分支 + merge 点。
  - 节点 check、PruneSignal、escape 语义（carrier/escape_via）、return_taint、self_contained/description/taint_failed。
- **脚本（tree-sitter）填入**：
  - **行号**：据 LLM 的节点/边语义锚点（变量名/赋值目标/callee 名）在函数体 AST 定位 → 填 node.line / edge.line。
  - 行号越界/找不到 → 标记可疑（不丢，保留供下游看），或回退重试（策略见 §10）。
- **clang 路径不采用**（需编译，当前不可行）。
- **可靠性**：大 DAG JSON 截断 → 沿用 `_extract_json_object` + 截断重试 + continue 续写。

## 4. 去重

- **key = (func_id, normalized_taint_signature)**。func_id 含类/命名空间限定 name + 完整参数 signature → overload 不合并、不同 scope 同名不合并。不含前置校验。
- **机制**：`processed_taints` PK = `(func_id, taint_signature)`；analyze 前 `try_reserve`（INSERT OR IGNORE，双检锁防并发重复分析）；analyze 失败 `delete` 占位。
- **回传污点**：return_taint 签名 ≠ 入口 → 不同 key → 不冲突，自然触发新分析（见 §6）。

## 5. 校验只记录

- 节点 `check` + 边 `condition` 都是 analyze 输出，落库供下游（挖掘）消费。
- analyze **不读前置校验链**：`_build_prompt` 不渲染前置校验链。
- 校验沿调用链累积（callee 的 ctx 带 caller 的 check）仅供挖掘上下文，**不进 dedup key**、**不影响传播**。挖掘如何消费见挖掘文档。

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
- **旧表废弃**：`taints` / `propagations` 表移除（DAG 是超集）。`processed_taints` 保留（去重锚点）。`orchestration`（边/ChainStep）表由队列项替代（见 §9）。
- description/self_contained/taint_failed 存 `taint_dag_meta`（一行/分析）或回写 functions 表。

## 9. 队列驱动的跨函数跟踪（编排重设计）

**不再递归 DFS**。改为**生产者-消费者工作队列**，本质是对跨函数污点传播图的 BFS：每个 (func, taint) 只分析一次，其 DAG 为权威数据，下游跟入项从 DAG 重放。

### 9.1 跟入项（work item，轻量引用，不重复记录）

DAG 是权威数据，跟入项只带**目标 + 溯源引用**，line/condition 等留在 DAG 里直接引用（D-5）。

- `callee`：`(callee_func_id, callee_taint_sig, origin_func, origin_node, origin_edge)` → 跟入 callee 分析该污点。
  - **taint_sig = callee 形参名归一化**（D-1）：caller `handle(a)`、callee 签名 `handle(pkt)` → 项的 taint_sig=`norm("pkt")`。
  - **多污点参数拆项**（D-2）：`handle(a, b)` 两参数均污点 → 拆 2 项 `(callee, norm(a))` + `(callee, norm(b))`，独立并行。
- `return_taint`：`(caller_func_id, return_taint_sig, callee_func, origin_edge)` → 回传重分析 caller。
- `escape_track`：`(origin_func, origin_edge)` → 触发 escape tracker（引用 DAG 的 extern/container 边，读 carrier/escape_via/sink_ref）。
- `indirect_track`：`(origin_func, origin_edge)` → 触发 indirect tracker（引用 DAG 的 callee 边，读 sink_ref=指针表达式）。

### 9.2 消费逻辑（核心：分析一次 + 重放下游）

队列项 `(func, taint)` 被拉取后：

1. `find_processed_taint(func, taint)`：
   - **未分析** → `try_reserve` 成功 → analyze → 存 DAG → 从**新 DAG** 重放下游项入队。
   - **已分析**（调用者不同但代码逻辑不变，没必要重分析，D-3）→ **不重分析** → 加载已存 DAG → 从**已存 DAG** 重放下游项入队（拼接后续传播图）。
2. 重放的下游项 = 该 DAG 的 `callee` 边 / `return` 边 / `extern`/`container` 边（→escape_track）/ 间接 `callee` 边（→indirect_track）。
3. 下游项入队后各自再走 9.2（BFS 传播），每项归结为某 (func, taint) → `try_reserve` 兑底去重。

### 9.3 tracker 结果经中继点接回图（E + GAP-6）

- **escape tracker**：extern/container 边的目标节点是**中继点**（g_cache/head 等外部可达对象）。tracker 找到读者 R 后，从中继点节点出一条 `kind=callee` 边到 R（读者经中继接回传播路径，不是另插独立边）；同时产出 `callee` 跟入项 `(R, taint_sig)` 入队（R 的 taint_sig 按 9.1 形参名规则）。
- **indirect tracker**：间接 callee 边 sink_ref=指针表达式 → tracker 解析真实函数 F（限定名）→ 回填该边 sink_ref=F（原地更新）+ 产出 `(F, taint_sig)` 队列项。
- 中继点节点是 DAG 一等节点（有 id、可多读者出边），escape 不是死路。

### 9.4 condition 不跨函数（D-4）

condition 只记录在 caller DAG 边上，供挖掘（独立文档）按路径条件判漏洞；**不进 callee 的 analyze**、不进队列项。callee 传播路径与被哪条条件触达无关。

### 9.5 并行与终止

- **并行**：多线程消费队列；同 (func, taint) 由 `try_reserve` 双检锁保证只 analyze 一次，重放可并发。
- **终止**（D-6）：**队列空 + 线程池均无在途任务**（所有 worker idle）= 污点跟踪完成。

## 10. 行号脚本填入策略（F）

- 脚本据 LLM 节点/边的语义锚点（变量名、赋值目标、callee 名）在 tree-sitter AST 定位行号。
- 找不到精确行 → 标记 `line_suspicious`（保留 LLM 给的近似/上下文行），不丢弃；下游可见。
- 全函数都无法定位 → 视为分析质量差，可触发重试（与 taint_failed 类似）。

## 11. 测试库（上线门禁）

- 建立**污点跟踪测试库**：覆盖各类情况的**构造最小 C/C++ 样例**（不用真实代码，可控、聚焦单一情况、易审；间接调用用最小 `(*fp)(x)` 样例）+ 预期 DAG。
- **预期 DAG = golden file**：首次产出经**人工校验**后锁定为 golden，后续回归比对（节点/边/kind/condition/check/prune）。
- **上线前必须全过**：系统对每个样例产出的 DAG 与 golden 匹配才算功能完整。
- 覆盖情况（初拟，待补）：函数内赋值链、分支互斥、分支汇合（merge）、复合条件、sanitizer 终止、sanitizer 约束、callee 透传、多污点参数拆项、extern 逃逸（global/field_alias）、container 逃逸、return 回传、间接调用（函数指针）、escape-source 冗余回传、低价值 callee 剪枝、overload 同名、不同类同名、已分析 (func,taint) 重放拼接。

## 12. 与当前的差异（迁移要点）

| 当前 | 设计 | 迁移 |
|---|---|---|
| 递归 DFS `_process`→`_run_path`→`_process` | 队列驱动工作项 + 多线程消费 | 重写编排为队列 |
| `propagations[]`+`taints[]` 扁平 | DAG 节点+边 | 新模型+新表，旧表废 |
| clang 填 call_line/branch/mutex | tree-sitter 填行号；condition/分支在 DAG 边 | 去 clang 依赖 |
| LLM 禁输出 condition | LLM 输出 CondTerm（递归布尔） | prompt 反转 |
| `validations` 混在 propagation | 拆 condition(边)/check(节点) | 拆分 |
| 校验影响传播 + 进 dedup | 只记录 + 不影响 + 不进 dedup | 去 pre_val |
| fork 会话链（A→A+B） | 独立会话（不 fork） | 去 fork/copyfile |
| `taint_params.names` list | 单污点 | 拆入口 |
| escape/indirect tracker 挂 propagation 字段 | 挂 DAG 边 + 结果回填图 | 适配新模型 |
| mining 在 analyze 同流程 | mining 拆独立文档 | 本文不管 |
| dedup `(func_id, taint_sig, pre_val)` | `(func_id, taint_sig)` | 去 pre_val |

## 13. 已确认决策

1. description / self_contained / taint_failed **保留**（self_contained=本函数自身 sink，控挖掘时序）。✅
2. **挖掘独立文档**，本文只管污点跟踪。✅
3. DAG **独立表**（nodes+edges），旧 taints/propagations 表**废弃**。✅
4. **队列驱动**（不递归遍历 DAG），跟入项入队、多线程并行消费；**(func,taint) 只分析一次，已分析则从已存 DAG 重放下游项拼接**（不重分析）。✅
5. tracker 结果**回填图**（解析出目标→插入 callee 边 + 入队）。✅
6. **行号脚本填入**（LLM 不输出行号）。✅
7. **不管专注模式**。✅
8. 每函数**独立会话**（func-taint 键，不 fork 链）。✅
9. **测试库**上线门禁；golden=人工校验首次产出；样例**构造**（不用真实代码）。✅
10. overload 不合并（func_id 含限定名+签名）。✅
11. 复合条件独立记录（CondTerm 递归）。✅
12. 队列项 taint_sig = **callee 形参名归一化**（D-1）。✅
13. 多污点参数 callee 边**拆 N 项**独立并行（D-2）。✅
14. **condition 不跨函数**，只记 caller DAG 边供挖掘（D-4）。✅
15. DAG 为**权威数据**，队列项轻量引用、不重复记录 line/condition（D-5）。✅
16. 终止 = **队列空 + 线程池无在途任务**（D-6）。✅
