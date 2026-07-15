# 测试库暴露的设计缺口

构建用例 01-16 时发现以下设计需补/改：

## GAP-1: 一条 callee 调用传多个污点参数（用例 06）

**问题**：`TaintEdge.taint: str`（单签名）。但 `B(t, t)` 一条调用传 2 个污点参数（x←t, y←t）。
**选项**：
- A. `taint` 改 `list[str]` + `param_taints` 映射（哪个实参对应哪个 callee 形参），一条边一调用，followup 按参数拆。✅ 一边一调用，干净。
- B. 每参数一条边（同 callee/line，不同 taint）→ 边冗余（callee/line 重复）。
**建议**：A。改 `TaintEdge.taint: list[str]`（单污点时 list 长度 1），加 `param_taints: [{param, taint}]`（callee 形参 ← caller 污点）。followup 按每个被污形参拆项。

## GAP-2: escape 边缺 carrier/escape_via/escape_subkind 字段（用例 07/08）

**问题**：`kind=extern/container` 边，escape tracker 需要 `carrier`（载体 p/ctx）、`escape_via`（enqueue/list_add）、`escape_subkind`（global/field_alias/container）才能解析读者。当前 `TaintEdge` 只有 `sink_ref`。
**建议**：`TaintEdge` 加可选字段：
- `escape_subkind`: `global | field_alias | container`（extern 细分 + container）。
- `carrier`: 载体变量名。
- `escape_via`: 逃逸调用名（仅记录）。
- `sink_ref`: 逃逸到达的外部容器/对象符号（head->q / g_cache / ctx->out）。
> extern/global 与 extern/field_alias 用 escape_subkind 区分；kind 统一 `extern`。

## GAP-3: overload 解析无编译（用例 13）

**问题**：`foo(t)` t=int，库里 `foo(int)` + `foo(char*)` 两个 overload。无 clang → LLM/script 按 arg 类型猜哪个 overload。猜错 → followup 走错函数。
**现状**：func_id 含 signature 能区分（不合并），但"调用点选哪个 overload"靠 LLM 语义。
**建议**：接受 LLM 按 arg 类型选（test 用例验证 LLM 选对）；func_id 保证去重不合并。LLM 输出 callee 时带 arg 类型推断，脚本用 func_id 库匹配。可靠性靠 test 门禁兜底。

## GAP-4: callee 名需限定（用例 14）

**问题**：`a->handle(t)`，库有 `A::handle` + `B::handle`。LLM 若只输出 `handle` → func_id 匹配歧义。
**建议**：prompt 要求 LLM 输出**限定 callee 名**（`A::handle`，含类/命名空间），与 func_id 库匹配。tree-sitter 可从调用点上下文补全限定（`a->` 的类型 A → A::handle）。prompt + tree-sitter 双保险。

## GAP-5: sanitizer "清洗" vs "守护" 的边界（用例 03 vs 04）

**问题**：`prune.sanitized` 的判据需明确。
- 03 `t = cleanse(t)`：t 被清洗成安全 → sanitized → 无下游边。✅
- 04 `if(len>100) return`：len 受约束 + 超长路径截断 → 是 **check + condition + 截断(无边)**，**不是** sanitized（len 仍污点，只是受限路径才传播）。
**建议**：文档明确 `sanitized` 仅指**污点被清洗成安全**（t 不再是污点）；guard/bounds 走 **check + condition**（不 prune，taint 仍传播只是路径受限）。已在用例 03/04 区分，文档 §2.4 补这句。

## GAP-6: sink_recorded 剪枝与 escape_track 的关系（用例 07/08）

**问题**：extern/container 边既触发 `escape_track`（tracker 找读者）又触发 `sink_recorded`（编排器记 sink 不跟入）。两者关系？
**建议**：extern/container 边 = sink 已记录（不直接跟入该边）→ 产出 `escape_track` 队列项（tracker 解析读者→回填 callee 边→入队读者）。即：`sink_recorded`（不跟入该边本身）+ `escape_track`（tracker 派生新 callee 跟入）。文档 §9.3 + §2.4 对齐这句。

---

## 待你拍板
- GAP-1：A（taint:list）还是 B（多边）？
- GAP-2：加 escape_subkind/carrier/escape_via 字段，确认？
- GAP-3：接受 LLM 选 overload + test 兜底，确认？
- GAP-4：prompt 要求限定 callee 名 + tree-sitter 补全，确认？
- GAP-5：sanitized 仅指清洗，guard 走 check+condition，确认？
- GAP-6：sink_recorded + escape_track 并存（记 sink + tracker 派生跟入），确认？

定后我补进设计文档 §2.1（TaintEdge 加字段）+ §2.4（sanitized 边界）+ §3（限定名）+ 继续写用例 09-16。
