# 污点跟踪测试库

每个用例 = 一个构造的最小 C/C++ 样例 + 预期 DAG（golden）+ 设计注记。
**用途**：① 上线门禁（产出 DAG 与 golden 比对）② 验证设计能否处理各场景（暴露 gap）。

## golden DAG JSON schema

```json
{
  "taint_signature": "归一化入口污点签名",
  "is_auto_source": false,
  "self_contained": false,
  "description": "函数功能",
  "nodes": [
    { "id": 0, "line": 0, "taint": "t", "parents": [], "checks": [], "prune": null, "is_source": false }
  ],
  "edges": [
    { "from": 0, "to": 1, "line": 1, "taints": ["a"],
      "kind": "inside|callee|extern|container|return|source",
      "condition": [], "sink_ref": null, "param_taints": null,
      "escape_subkind": null, "carrier": null, "escape_via": null }
  ],
  "followups": [
    { "kind": "callee|return_taint|escape_track|indirect_track",
      "target_func": "B", "target_taint": "pkt", "origin_edge": "0->1" }
  ]
}
```

## 用例清单（全 ✅）

| # | 用例 | 覆盖 |
|---|---|---|
| 01 | 赋值链 | inside 边串联 |
| 02 | 分支汇合 merge | DAG 多 parent |
| 03 | sanitizer 清洗 | prune=sanitized（仅清洗） |
| 04 | sanitizer 约束 | check + condition（guard，非清洗） |
| 05 | callee 透传 | callee 边 + 形参名归一 |
| 06 | 多污点参数 | taints:list + param_taints 拆项 |
| 07 | extern global | escape_subkind=global + 中继 |
| 08 | container | carrier/escape_via + 中继 |
| 09 | return 回传 | return 边 + 回传项 + A 的 r 轮 source |
| 10 | 间接调用 | sink_ref=指针 + indirect_track 回填 |
| 11 | escape-source 冗余回传 | #11 skip（A 已持有 g_cache） |
| 12 | 低价值 callee 剪枝 | prune=low_value_callee |
| 13 | overload 同名 | func_id 签名区分（LLM 选） |
| 14 | 不同类同名 | 限定名 callee（tree-sitter 补全） |
| 15 | 已分析重放拼接 | (func,taint) 只分析一次 + 重放下游 |
| 16 | 复合条件 | CondTerm Compound（独立记录） |
| 17 | 污点来源=返回值 | kind=source（getenv 返回） |
| 18 | 被动输入 out-param | kind=source（read 写 buf） |

## GAP 决议（全定，已并入设计文档）

- **GAP-1** → A：`taints:list[str]` + `param_taints`，一边一调用、followup 按形参拆。✅
- **GAP-2** → TaintEdge 加 `escape_subkind`/`carrier`/`escape_via`。✅
- **GAP-3** → LLM 按 arg 类型选 overload（无编译），func_id 兜底不合并，test 验证。✅
- **GAP-4** → callee sink_ref 限定名（`A::handle`），LLM 输出 + tree-sitter 补全。✅
- **GAP-5** → sanitized 仅指清洗成安全；guard/bounds 走 check+condition（不 prune）。✅
- **GAP-6** → extern/container 边目标=中继点；tracker 找读者后从中继点出 callee 边接回路径 + 入队。✅
