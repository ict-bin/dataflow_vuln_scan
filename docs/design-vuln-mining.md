# 完整模式漏洞挖掘设计

> 状态: 设计对齐中，未实现。依赖污点跟踪设计（`design-taint-analysis.md`）产出的单函数 DAG。
> 范围: 正向数据流链构建、挖掘触发时序、跨函数链拼接、去重、DAG 查询工具、测试库。
> 四维度判定（D1-D4）沿用现有 vuln-miners/default.md 的"默认非漏洞找反证"立场。

## 0. 设计原则

1. **taint 专注单函数跟踪，不扩展**（Q4）：taint 产单函数原始 DAG（不深入 callee、不折叠 callee 效果）。callee 对污点的效应（清洗/转换/派生）由**挖掘**在读 callee DAG 时拼装。
2. **正向从入口建数据流链**（Q1）：挖掘从函数入口污点出发，正向按 call_line 顺序遍历，拼装 callee 效应，构建数据流链——天然按序看到 check→unpack→handler 对污点的处理。
3. **按函数灵活触发**（Q2）：某函数**无传出点**（叶子）或**所有传出点（直接 callee/return/escape 目标）的 taint DAG 已就绪** → 该函数可挖。不等全部 taint 跟踪完。
4. **每个传入都挖，不靠命名过滤**（Q3）：不假设函数命名规律，所有 (func, taint) 入口都跑挖掘。是否漏洞由 LLM 判，不靠函数名预筛。
5. **默认非漏洞、找反证**：D1-D4 缺一不可。
6. **AI 为中心、无白名单**：危险 sink / 防御有效性 / 源可控性 全 LLM 语义判。
7. **独立会话**（Q6）：挖掘 (func, taint) 独立 agent 会话，读 DAG + 完整源码 + 工具，不继承 taint 会话历史。

## 1. 挖掘模型（正向建链 + 按函数触发）

### 1.1 触发时序（Q2 灵活 per-function）

taint 跟踪是 BFS 队列，产各 (func, taint) DAG。挖掘**不等全部 taint 完**，按函数灵活触发：

某 (func, taint) **可挖**当：
- **无传出点**（叶子：无 callee/return/escape 边，即 self_contained 且无 callee），或
- **所有传出点目标均已分析**（该函数 DAG 的 callee/return/escape 边指向的目标 (func, taint) 的 taint DAG 已落库）。

→ 传出点就绪即触发该函数挖掘（per-function join on 直接传出点）。传出点目标在 BFS 中比 caller 晚完成，故挖掘按"叶子→caller"波次推进（近反向拓扑）。

> **链的深度**：本函数挖掘只拼**直接传出点**层的效应（f→check→unpack→handler，一层）。handler 若是用户函数（非直接危险 sink），其内部 sink 由 **handler 自己的挖掘**（handler 传出点就绪时触发）处理。全链 = 各函数挖掘段的拼接，无单一任务建全传递闭包（防爆）。

### 1.2 正向建链流程（Q1 从入口出发）

对可挖的 (func, taint)：

1. 从入口污点节点（source/param）出发。
2. 按 call_line 顺序遍历本函数 DAG 的传播路径（inside 边 + callee 边）。
3. 对每个 callee 边，读 callee 的 DAG（`dag_callee`）取其对污点的**效应摘要**：
   - 清洗（`prune=sanitized`）→ 污点在此 callee 后变干净。
   - 转换/派生（return_taint / 新污点节点）→ 污点形态变化。
   - 不变（无 sanitizer、无派生）→ 污点原样透传。
4. 拼装数据流链：入口 → [callee1 效应] → [callee2 效应] → … → sink。
5. 沿链判断每个潜在 sink（本函数 in-function sink + 直接 callee 危险 sink）。
6. D1-D4 四维度判定，全过 → finding。

> 例 `f(msg){ check(msg); unpack(msg); handler(msg); }`：链 = msg 入口 → check（读 check DAG: 是否清洗 msg？）→ unpack（读 unpack DAG: 是否派生/转换？）→ handler（读 handler DAG: handler 是否危险 sink？）。按序拼，msg 在 handler 处的状态由 check/unpack 效应决定（D3 顺序依赖天然满足）。

### 1.3 跨函数链拼接

本函数链只到直接 callee 层。跨函数全链由各函数挖掘段拼接：
- f 挖：f→check/unpack/handler 段 + handler 若直接危险 sink 则判；handler 是用户函数则 f 只记"传给 handler"，handler 的内部 sink 由 handler 挖。
- handler 挖（handler 传出点就绪触发）：handler→handler 的 callees 段。
- 全链 = f 段 + handler 段 + …，各段 finding 若指向同一 sink → §5 跨函数去重。

## 2. DAG 查询工具（Q2，LLM 用）

挖掘 agent 工具集（操作已存 DAG + 源码，禁止全盘 find/grep）：

| 工具 | 作用 |
|---|---|
| `dag_get(func_id, taint_sig)` | 取本函数 DAG（节点/边/condition/check/prune） |
| `dag_callee_effect(func_id, taint_sig, callee_edge)` | 取 callee 边目标 DAG 中**对污点的效应摘要**（清洗/转换/派生/不变） |
| `dag_callee(func_id, taint_sig, callee_edge)` | 取 callee 完整 DAG（需细看时） |
| `dag_walk_children(func_id, taint_sig, node_id)` | 正向走 children（建链） |
| `dag_find_sink(func_id, taint_sig)` | 找本函数 DAG 的潜在 sink 节点（callee-danger/escape/return） |
| `get_func_source(func_id)` | 取函数完整源码（D1 逐行核，Q5） |
| `dag_callers(func_id, taint_sig)` | 反查谁调用本函数（跨函数回溯入口用，按需） |
| `v2_db lookup/symbol` | 沿用（宏/符号/外部库函数行为） |

> `dag_callee_effect` 是核心：把 callee DAG 里"对该污点的处理"压缩成摘要（清洗/转换/派生/不变），供建链直接用，降低 LLM 读全 callee DAG 的成本。

## 3. 挖掘输入（每函数挖掘任务）

| 输入 | 说明 |
|---|---|
| 本函数 DAG | 节点/边/condition/check/prune（权威） |
| 本函数完整源码 | D1 逐行核（Q5，独立会话不频繁压缩） |
| 直接 callee DAG / 效应摘要 | 建链用（`dag_callee_effect`） |
| `description` | 本函数功能 |
| DAG 查询工具 | 建链 + 取源码 + 跨函数（§2） |

## 4. sink 识别（LLM 判，无白名单，不靠命名）

沿正向链，LLM 判每个潜在 sink：
- **直接危险 callee**：sink_ref 是外部/已知危险操作（memcpy/strcpy/system/exec/deref/free-use/…）→ 本函数判。
- **用户函数 callee**：不靠命名判（`check_*` 可能不校验、`handle_*` 可能危险）→ 读其 DAG/源码（`dag_callee` + `get_func_source`）确认内部有无 sink；其内部 sink 由该 callee 自己挖，本函数只记传播。
- **escape 边**（extern/container）：数据流出 → 本函数判（泄露/SSRF/注入）。
- **return 边**：返回未净化污点至信任边界 → 本函数判。
- **inside 边**：非 sink。

> 关键（Q3）：不靠函数名预筛"这个 callee 大概没洞"。所有传入都挖，每个 callee 都读其 DAG 确认效应/sink，由 LLM 判。

## 5. 去重

- **finding_id = sha1(function_name | vuln_type | line)**（sink 位置）。INSERT OR REPLACE。
- **跨函数/跨段去重**：全链各段可能对同一 sink 都判出 finding。去重：sink 节点位置（func+type+line）相同 → 合并；**离 sink 近的段（含 sink 的函数）优先，上游传播段不重复报同一 sink**。
- 漏洞计数同步 MySQL（沿用）。

## 6. 四维度判定（沿用，正向链适配）

- **D1 code_accurate**：sink 处操作 + 跨函数 callee 效应断言须有 callee DAG 或源码取证（`dag_callee`/`get_func_source`）。
- **D2 path_reachable**：沿正向链回溯到入口，入口是否外部可控源（网络/文件/SQL/命令行/IPC/反序列化）；不可控 → 丢弃。
- **D3 unmitigated**：链上各 callee 的效应（清洗/约束）是否全部可绕——**按序**：check 清洗了 msg？unpack 约束了？存在不可绕有效清洗 → 丢弃。不继承"已校验=安全"，逐 callee 证。
- **D4 security_impact**：实质后果（机密/完整/可用），排除仅 DoS/概率门控/哈希不可控等。

## 7. 测试库

建挖掘测试库（构造样例 + 预期 findings），覆盖：
- **真 vuln**：buffer-overflow / null-deref / ssrf / uaf / 命令注入 / 信息泄露 —— 须过 D1-D4。
- **顺序依赖**（核心）：`f{check(msg);unpack(msg);handler(msg);}` —— check 清洗→handler 无洞；check 未清洗→handler 有洞。验证正向建链按序拼效应。
- **误报**：callee 清洗（prune sanitized）/ 源不可控（D2）/ 路径不可达 / 仅 DoS（D4）—— 须丢弃。
- **跨函数 vuln**：source 在 A、sink 在 C、中转 B —— 各段拼接 + 跨段去重。
- **escape vuln**：container/global 泄露。
- **复合条件路径**：condition 分支下才触发的 sink。
- **return 边漏洞**。
- **命名陷阱**：`check_*` 实际不校验 / `handle_*` 实际危险 —— 验证不靠命名、读 DAG 确认。

> golden = 人工校验过的首次产出。

## 8. 与当前的差异（迁移要点）

| 当前 | 设计 | 迁移 |
|---|---|---|
| 按函数挖一次（mine_vulns，fork 链 session） | 按函数正向建链 + 独立会话 | 改流程 |
| 前向链靠 fork 继承调用链历史 | 正向建链读 callee DAG/效应摘要（不继承） | 去 fork |
| self_contained 控 step4/step6 | 传出点就绪即挖（灵活 per-function） | 改触发 |
| callee 行为靠 v2_db 读源码 | `dag_callee_effect` 摘要 + 按需 `get_func_source` | DAG 效应优先 |
| 靠函数名/传播点预筛 | 所有传入都挖，不靠命名 | 去预筛 |
| finding_id=func+type+line | 同 + 跨段去重（sink 近者优先） | 加去重 |
| 无 DAG 查询工具 | 新增 dag_* 工具集（建链/效应/源码） | 新工具 |
| mining 内嵌 taint 流程 | taint 与 mining 分离 | 解耦 |

## 9. 已确认决策

1. **后续挖 + 正向从入口建数据流链**（Q1）：从入口正向按序拼 callee 效应建链。✅
2. **按函数灵活触发**（Q2）：无传出点或所有传出点 taint DAG 就绪即挖（不等全部）。✅
3. **所有传入都挖，不靠命名过滤**（Q3）：不假设命名规律，每个 (func,taint) 都挖，LLM 判。✅
4. **taint 专注单函数，不扩展**（Q4）：callee 效应由挖掘读 callee DAG 拼，taint 不折叠。✅
5. **提供完整源码**（Q5）：本函数完整源码 + 工具按需取 callee 完整源码（独立会话不频繁压缩）。✅
6. **独立会话**（Q6）。✅
7. 四维度 D1-D4 沿用（默认非漏洞找反证），D3 按序查链上 callee 效应。✅
8. finding_id=func+type+line + 跨段去重（sink 近者优先）。✅
