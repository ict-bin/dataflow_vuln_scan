# 污点跟踪 + 漏洞挖掘 统一测试库

每个用例 = 构造最小 C/C++ 样例 + **taint DAG golden**（`expected_dag.json`）+ **mining findings golden**（`expected_findings.json`）。
**协同工作**：taint 跟踪产 DAG → mining 消费 DAG 出 findings，同一用例验证整条流水线。

## golden schema

`expected_dag.json`（taint 跟踪产出）:
```json
{ "taint_signature": "...", "nodes": [...], "edges": [...], "followups": [...] }
```

`expected_findings.json`（mining 产出）:
```json
{
  "mining_target": {"func": "f", "taint": "x"},
  "forward_chain": [{"step": 0, "source": "...", "taint_state": "tainted"}, {"step": 1, "callee": "...", "effect": "sanitized|unchanged|...", "sink": true}],
  "findings": [{"vuln_type": "...", "severity": "...", "location": {"function","line"}, "dag_path": [...], "dimensions": {"D1":{...},"D2":{...},"D3":{...},"D4":{...}}, "confidence": 0.8}],
  "discarded": [{"at_node": "...", "reason": "D3=FAIL: ..."}]
}
```

## 用例清单

### 污点跟踪（01-18，含 mining golden 验证整链）

| # | 用例 | taint 覆盖 | mining 期望 |
|---|---|---|---|
| 01 | 赋值链 | inside 串联 | 无洞（use 非危险） |
| 02 | 分支汇合 merge | DAG 多 parent | 无洞 |
| 03 | sanitizer 清洗 | prune=sanitized | 无洞（已清洗） |
| 04 | sanitizer 约束 | check+condition | 无洞（guard 约束） |
| 05 | callee 透传 | 形参名归一 | 无洞 |
| 06 | 多污点参数 | taints:list+param_taints | 无洞 |
| 07 | extern global | escape_subkind+中继 | escape 漏洞候选 |
| 08 | container | carrier/escape_via+中继 | escape 漏洞候选 |
| 09 | return 回传 | return 边+回传 | 无洞（透传） |
| 10 | 间接调用 | sink_ref=指针+indirect_track | 无洞 |
| 11 | escape-source 冗余 | #11 skip | 无洞（skip） |
| 12 | 低价值 callee 剪枝 | prune=low_value_callee | 无洞（剪枝） |
| 13 | overload 同名 | func_id 签名区分 | 无洞 |
| 14 | 不同类同名 | 限定名 callee | 无洞 |
| 15 | 已分析重放拼接 | 只分析一次+重放 | 无洞 |
| 16 | 复合条件 | CondTerm Compound | 无洞（无 sink） |
| 17 | 来源=返回值 | kind=source | 无洞 |
| 18 | 被动输入 out-param | kind=source | 无洞 |

### 漏洞挖掘（19-27，三件套：sample + dag + findings）

| # | 用例 | 挖掘覆盖 | 期望 |
|---|---|---|---|
| 19 | buffer-overflow | 真 vuln, 直接危险 callee | finding ✅ |
| 20 | 顺序依赖(清洗) | check 清洗→handler 无洞 | 丢弃(D3) ✅ |
| 21 | 顺序依赖(未清洗) | check 只 guard→handler 有洞 | finding ✅ |
| 22 | 误报 sanitizer | cleanse 清洗 | 丢弃(D3) ✅ |
| 23 | 误报源不可控 | /proc 内核源 | 丢弃(D2) ✅ |
| 24 | 跨函数 vuln | A→B→C, 各段拼接+跨段去重 | C 段 finding, B/A 丢弃 ✅ |
| 25 | 命名陷阱 | safe_copy 名安全实危险 | finding ✅（不靠命名） |
| 26 | return 边漏洞 | 返回未净化至边界 | finding ✅ |
| 27 | 复合条件 sink | condition 分支下 sink | finding ✅ |

> golden = 人工校验过的首次产出（同 taint 库方法）。
> 20/21 是顺序依赖核心对（清洗 vs 不清洗），验证正向建链按序拼 callee 效应重建污点状态。

### escape 规则边界（28-30）

| # | 用例 | escape 覆盖 | 期望 |
|---|---|---|---|
| 28 | 跨入参 escape | data 污点 -> 另一个入参 buf | extern ✅（真 escape, 跨入参）|
| 29 | 局部别名不是 escape | header=msg 别名, 写 header->field | inside ✅（不是 escape, 不触发 tracker）|
| 30 | carrier 去重 | 同一全局 3 行写入 | 3 条 extern 边但只 1 条 escape_track ✅ |

> 28/29 是 escape 判定核心对（跨入参 vs 同入参别名），验证 escape 规则边界。
> 30 验证 orchestrator 按 carrier 去重 escape_track 工作项。
