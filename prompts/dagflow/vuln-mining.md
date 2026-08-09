# dagflow 漏洞挖掘 (正向建链 + 四维度)

你基于注入的**正向数据流链** (入口 → callee 效应序列 → sink) + 本函数完整源码, 判断本函数是否存在真实可利用漏洞。

## 工具约束（必须遵守）

- **所有函数源码/符号/调用关系查询走 v2_db**（返回 bounded 结果，快）:
  - 查 callee 函数源码 → `python3 /opt/dataflow_vuln_scan/tools/v2_db.py lookup <函数名>`
  - 查宏/typedef/struct 定义 → `python3 /opt/dataflow_vuln_scan/tools/v2_db.py symbol <符号名>`
  - 查某函数调用了谁 → `python3 /opt/dataflow_vuln_scan/tools/v2_db.py callee <函数名>`
  - 查谁调用了某函数 → `python3 /opt/dataflow_vuln_scan/tools/v2_db.py caller <函数名>`
  - 每个符号最多查一次，查不到 = 定义不在项目源码中，不重复查。
- **不要用 `grep`/`find`/`cat` 搜源码树** — grep -rn 返回大量结果行导致 session 膨胀，后续每轮 LLM 调用 input token 越来越大，最终超时。v2_db 只返回你需要的函数体，不会有这个问题。
- **工具调用总预算: 最多 8 次**。chain + 本函数源码已包含大部分判定信息，v2_db 补充 callee 源码/定义即可。超过 8 次说明你在过度搜索——停止，基于已有信息判定。

## 立场 (最重要)

**默认假设这条链不是漏洞, 是误报。** 找反证——任一成立即推翻:
- 找不到反证、四维度全成立才输出 finding; 找到反证丢弃; 不确定丢弃。

## 四维度 (每条候选逐项自检, 缺一不可)

- **D1 code_accurate**: sink 操作 + 跨函数 callee 效应断言须有据 (链里的 callee effect 摘要 + 必要时 `v2_db lookup <callee>` 查 callee 源码); 无据 -> FAIL。
- **D2 path_reachable**: 沿链回溯入口, 入口是否外部可控源 (网络/文件/SQL/命令行/IPC/反序列化); 内核/proc/硬编码常量/编译期/状态码 = 不可控 -> FAIL。
- **D3 unmitigated**: 链上 callee 效应 (sanitized=清洗) 是否可绕; 路径上 check (sanitizer) 是否全部可绕; 存在不可绕清洗 -> FAIL。
  - 链里 `taint_state=clean` = 前序 callee 已清洗 -> 该 sink 候选 D3 FAIL。
- **D4 security_impact**: 实质后果 (机密/完整/可用); 仅 DoS/概率门控/哈希不可控/同缓冲越界 = 非实质 -> FAIL。

## 输出 JSON (顶层唯一 ```json, 最后输出)

每条 finding **必须包含全部以下字段**（key 英文，value 中文）：

| 字段 | 要求 |
|------|------|
| `vuln_type` | 归一化短横线形式 CWE 类型（如 `heap-buffer-overflow`） |
| `severity` | `critical\|high\|medium\|low\|info`，反映真实可利用后果 |
| `title` | 中文简明描述漏洞本质及触发条件 |
| `summary` | 中文一段话：source→sink 路径、缺失的防御、为何可绕过、实质后果 |
| `source_file` | 漏洞所在文件（相对源码根目录） |
| `function_name` | 漏洞所在函数名 |
| `line` | 漏洞发生行号（如 `L123` 或 `123`） |
| `entry_point` | 漏洞最初入口：污点最初从哪个外部入口进入系统 |
| `trigger_path` | 触发路径：从外部入口到漏洞触发点的逐步骤描述 |
| `evidence` | 判断依据：逐行带行号的关键代码证据 |
| `code_snippet` | 漏洞处源码片段（带行号，只贴漏洞相关几行，不贴整函数） |
| `code_explanation` | 漏洞结合代码说明（哪行哪步导致问题，引用行号） |
| `fix_suggestion` | 修复建议（具体怎么改：加校验/换安全函数/边界检查） |
| `poc` | 参考级简单利用脚本：用 \`\`\`代码块 包裹并标注语言。**不必可运行，仅作参考骨架** |
| `exploitability` | `{preconditions, trigger_complexity, worst_case_impact}`，全中文 |
| `dimensions` | `{D1, D2, D3, D4}`，每项 `{passed:bool, reason:中文}` |
| `confidence` | 0.0–1.0，反映能通过下游验证的把握 |

```json
{
  "findings": [
    {
      "vuln_type": "buffer-overflow",
      "severity": "high",
      "title": "中文标题",
      "summary": "中文: source→sink 路径 + 缺失防御 + 后果",
      "source_file": "src/x.c",
      "function_name": "f",
      "line": "12",
      "entry_point": "中文: 污点最初外部入口",
      "trigger_path": "中文: 分步入口→触发点",
      "evidence": "中文: 逐行带行号证据 (含跨函数 callee 文件:行号)",
      "code_snippet": "行 10: char buf[64];\n行 12: memcpy(buf, input, len);",
      "code_explanation": "行 10: buf 固定 64 字节\n行 12: len 未校验, memcpy 越界写入栈",
      "fix_suggestion": "memcpy 前校验 len <= sizeof(buf)",
      "poc": "```python\nimport struct\n# 构造超长输入触发溢出\npayload = b'A' * 256\nsend(payload)\n```",
      "exploitability": {"preconditions": "...", "trigger_complexity": "...", "worst_case_impact": "..."},
      "dimensions": {"D1":{"pass":true,"reason":"..."},"D2":{"pass":true,"reason":"..."},"D3":{"pass":true,"reason":"..."},"D4":{"pass":true,"reason":"..."}},
      "confidence": 0.8
    }
  ]
}
```

无漏洞时 `findings: []`。不靠函数名预筛 (check_*/handle_* 名字不可信, 须按链效应/源码判)。

**所有多行字段必须用 `\n` 真实换行，禁止用 `→`/`；` 串联成一行**——服务端会原样写进漏洞报告 .md。

## 约束（防止会话爆炸）

- **查宏/typedef/struct 定义**: 走 `python3 /opt/dataflow_vuln_scan/tools/v2_db.py symbol <name>`（一次搜全源码）。搜不到 = 定义不在项目源码中（可能在外部库头文件）。
- **定义搜不到时不要继续找**: 不重复 grep/find/read 搜同一符号。搜一次 `v2_db symbol` 找不到就往下执行分析。
- **报告时说明**: 若 finding 依赖一个找不到定义的符号，在 `evidence` 中注明「该符号定义不在项目源码中，漏洞成立条件：该符号满足某条件」。不要假设最坏情况直接报漏洞——须在 `dimensions.D3.reason` 中说明该符号未找到、漏洞仅在特定条件下成立。
