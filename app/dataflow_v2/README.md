# dataflow-v2: 数据流漏洞挖掘完整重实现 (debug 分支)

在 `dev/dataflow-v2` 分支上从零重写数据流漏洞挖掘。补丁式改进已无法解决
跟踪正确性问题 (兄弟分支串联、幽灵边、状态错误合并等), 改为四库驱动的
路径敏感 DFS 重写。

## 四库 (sqlite3, run/dataflow-v2/)

| 库 | 文件 | 载体 | 核心字段 |
|---|---|---|---|
| 函数库 | functions.db | 函数 | file, name, signature, start/end_line, body_path, func_hash, description, processed_taints[] |
| 污点库 | taints.db | 污点 | name, signature, file, function, next_propagations[], description |
| 传播库 | propagations.db | 传播 | source/target taint name+sig, condition, validations[], description, source/target_func_id |
| 编排库 | orchestration.db | 路径边 | path_id, source/target function+sig+func_id, taint_params, depth, edge_order, status |

- **函数体**存 `run/functions/<rel>__<name>__<hash>.c`, 库里只存 body_path 索引。
- 四库物理隔离, 编排库冗余存函数名/签名避免跨库 JOIN。

## 分析过程 (步骤 6)

1. **函数提取**: `ensure_file_indexed` — 若函数库无该文件函数, tree-sitter
   提取全部函数入库 + 函数体落盘 `run/functions/`。
2. **LLM 污点分析**: 在前置 session 基础上 fork 新会话, 分析函数功能 + 污点
   传播路径 → 建污点库/传播库记录。
3. **clang 分支判定**: 互斥 if/else-if/switch arm → 路径分叉 (复用
   `clang_analyzer` 的 branch stack + mutex 判定, 但改为产出**独立路径**
   而非软隔离 note)。
4. **数据入库**: taint/propagation/orchestration。

## 编排器 (深度优先, 路径敏感)

```
A(msg){ B; C(msg); if(x) D(msg); else E(msg); F(msg); }
  → 路径1: A->C->D->F
  → 路径2: A->C->E->F

D(msg){ G(msg); }              → 内联展开: A->C->D->G->F
E(msg){ g_msg=msg; }           → 外部变量, 跟踪 LLM 找 H/I:
                                  A->C->E->H->F ; A->C->E->I->F
```

### 漏洞挖掘时机 (后序)
- **叶子函数** (无出传播, 如 C/G/F): 污点分析完成 → **立刻** fork 漏洞挖掘。
- **非叶子函数** (如 A/D/E): 等全部子路径完成 → 再挖 (此时才知 msg 在该函数
  完整处理方式)。
- E 场景: E 的出传播是外部变量 → H/I 分叉; E 的挖掘等 H、I 都完成 (后序一致)。

## 去重 (三重)
到达函数时, 若 `(source_dir_id, parent_task_scope_id, 函数签名→func_id,
污点参数→taint_signature)` 已在 `processed_taint_scope_claims` 命中 → 跳过。
`parent_task_scope_id` 使用父任务 ID；没有父任务时统一使用
`__dvs_no_parent_task__`。`processed_taints` 仍保留每个任务的审计记录。
`store.find_processed_taint()` 实现。

## 当前进度 (准备阶段)
- [x] 四库 schema + 访问层 (`store.py`) + 测试
- [x] 数据模型 (`models.py`)
- [x] tree-sitter 函数提取 + 落盘 (`function_extractor.py`)
- [x] DFS 编排器骨架 + 路径模型 + 后序挖掘框架 (`orchestrator.py`)
- [ ] LLM 污点分析 fork 接入 (`AnalysisCallbacks.analyze_function`)
- [ ] clang 分支判定 → 路径分叉 (替代软隔离)
- [ ] 外部变量跟踪 LLM (`resolve_external_propagation`)
- [ ] 漏洞挖掘 fork (`mine_vulns`)
- [ ] 线程池并发 (目前骨架同步排空)
- [ ] prompts/v2/taint-analysis.md

## 待定设计点 (需确认)
1. **污点参数标识**: 当前用 `TaintParamInfo{positions, signature, names}`
   (位置优先 + 签名 + 名)。跨函数 A 的 msg → C 的 pkt, 用位置 [0] + 归一化
   签名匹配, 名字仅辅助。✅ 倾向位置, 待确认。
2. **DB 粒度**: 4 个独立 .db 文件 (匹配 "几个数据库") vs 1 文件 4 表。
   当前选 4 文件; 若跨库查询变多可合并。
3. **E 场景挖掘时机**: 当前后序 (E 等 H/I)。备选: E 自身 sink 自洽 → E 立即挖。
4. **clang 分支判定**: 确认 "lang" = clang, 复用 `clang_analyzer` 的 mutex 判定
   但产出独立路径 (v1 是软隔离 note)。
