---
name: write-taint-graph
description: 生成结构化单函数污点图谱 JSON，用于数据流漏洞挖掘。
---

# write-taint-graph skill

不要写任何中间产物文件。不要创建 `taint-graph.json`、`tainted.list`、`taintvars.json`、`dataflow-*.md` 或 `taint-flow-*.md`。

在最终回复中直接输出一个 JSON 对象。服务端会解析该 JSON 并将污点、边、跟入点和发现持久化到任务级 SQLite 数据库。

**所有文本字段必须使用简体中文**（JSON key 保持英文）：
- `taints[].description`：中文描述污点来源
- `edges[].evidence`：中文描述代码证据
- `edges[].sanitizer_effect`：中文值（`完整清洗`/`部分清洗`/`未清洗`/`未知`）
- `edges[].validation`：中文描述
- `edges[].termination_reason`：中文描述终止原因
- `followups[].reason`：中文描述跟入原因

必需的顶层 key：
- `function`
- `source_file`
- `taints`
- `edges`
- `followups`
- `termination`

每条边必须包含行号证据和清洗/校验状态。不要无声丢弃污点：如果它终止了，记录原因。

`followups` 是唯一的 callee 交接通道。每项必须包含 `file`、`function`、`line`、`tainted_params` 和 `reason`。

## 输出格式约束（必须遵守）

- 推理/思考过程中，**禁止**在 markdown 代码块（` ``` `）里写任何 JSON 片段或部分字段示例；需要举例时只用纯文字描述。
- 最终的 taint-graph JSON 必须是回复中**最后一个** ` ```json ` 代码块，且**只输出一次**，顶层包含全部必需 key（`function`/`source_file`/`taints`/`edges`/`followups`/`termination`）。
- JSON 代码块之后**不要再输出任何内容**（不要追加 `<result>` 摘要或其他文字）；如需摘要，写在 JSON 之前。
- 本函数无污点传播时，`edges` 与 `followups` 设为 `[]`，`termination` 按实际填写，仍须输出完整 JSON。
- 输出不符合上述 schema 会被系统要求重新输出，请一次到位。
