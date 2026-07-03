# 数据流污点分析：单函数传播分析 Fork

你在从前置 session 复制出的 fork session 中工作。你的任务是**只分析当前这一个函数**：
提取函数功能说明、入口污点在本函数内的传播路径，并判断本函数对污点的处理是否自洽。
**不要跨函数递归**——callee 的内部行为不在你的上下文里，禁止臆断。

## 语言要求（最高优先级）

所有文本输出使用简体中文。JSON key 保持英文，`description`/`condition`/`content`/
`validations.content` 等 value 用中文。`signature`/`target_function`/`target_taint`
用代码原文标识符（不翻译）。

## 输入

- 目标函数体（已从 `run/functions/` 读出，由服务端注入上下文）。
- 入口污点参数：**位置**（0-based）+ 签名 + 名字。
- 前置校验链：从根函数到本函数，调用链上已累积的校验（condition+content 列表）。

## 必须输出 JSON

```json
{
  "description": "本函数功能说明（一句话职责）",
  "self_contained": true,
  "taints": [
    { "name": "msg", "description": "入口报文指针" }
  ],
  "propagations": [
    {
      "source_taint": "msg",
      "target_taint": "pkt",
      "target_function": "C",
      "validations": [
        { "condition": "msg->length>0", "content": "长度已校验" }
      ],
      "description": "msg 透传给 C 的 pkt 参数",
      "is_external": false
    }
  ]
}
```

## 字段说明 (LLM 只输出语义字段; 结构字段由 clang/脚本提供)

LLM 只负责**污点跟踪语义**: 哪些变量被污染 (source_taint/target_taint)、污点流到哪个 callee
(target_function, 仅填 callee 名)、传播过程的校验 (validations)、是否传播到外部变量
(is_external)、行为描述 (description, 如"返回借用指针""分配新缓冲""不释放")。

**不要输出** call_line / condition / is_indirect_call / dispatch_kind / signature /
target_file —— 这些由服务端 clang/脚本从 AST 精确获取 (行号/分支/间接调用/签名/文件)。

- `source_taint`：本函数内被污染的变量名 (入口污点或派生污点)。
- `target_taint`：**callee 接收的污点参数名**——即 callee 签名中的形参名, 代表污点传入 callee 后在该参数上的名称。
  **不是 callee 的返回值或内部产物**。如果本函数调 `xmlFdOpen(filename, 1, &ret)`,
  `target_taint` 应填 `filename` (传给 callee 的参数), 不是 `fd` (callee 的返回值)。
  ❌ `source_taint="filename"`, `target_taint="fd"` (fd 是返回值, 错误)
  ✅ `source_taint="filename"`, `target_taint="filename"` (filename 是 callee 参数, 正确)
- `target_function`：本函数**真实调用**的 callee 名 (clang 会校验并定位精确 CallExpr)。
  传播到外部/全局变量时留空 + `is_external=true`。
- `validations`：本传播过程中 (从源污点到调用点) 累积的校验, 每项 `{condition, content}`。
  包括上游传入的前置校验中**在本函数内仍然生效**的部分, 以及本函数新增加的校验。
- `description`：传播语义 + callee 行为事实 (如"C 返回 PyBytes_AsString 借用指针, 非 xmlMalloc"),
  供下游漏洞挖掘识别跨函数漏洞 (如 double-free)。
- `is_external`：仅当污点被写入**非本函数入参、且非本函数内定义的变量**时为 true（全局/静态变量, 如 `g_msg = msg`）。通过局部变量/入参指针访问的 struct 字段不是外部变量。污点作为参数传给 callee 时永远为 false。不要替 callee 报告其内部行为。
- **函数指针/回调间接调用**：若污点经由函数指针调用传出（如 `ctxt->sax->processingInstruction(...)`、`(*fp)(msg)`、`ptr->handler(msg)`），`target_function` 填被调用的**函数指针表达式**（如 `ctxt->sax->processingInstruction`），`is_external=false`。服务端 clang 会自动判定为间接调用 (is_indirect_call) 并触发 function_pointer tracker 搜注册点解析真实处理函数。**不要把函数指针调用标为 is_external**。

## self_contained 判定准则（设计核心）

`self_contained` 由你判断：**本函数对污点的处理是否自洽**——即仅靠本函数自身即可判定
是否存在 sink/漏洞，还是必须等下游 callee 的处理结果才能判定。

- **true（立即挖）**：本函数内已有完整 sink。例如：
  - 污点直接喂给危险操作（`memcpy`/`strcpy`/`sprintf` 到定长缓冲、`system`/`exec`、
    `free` 后续使用、指针解引用越界）；
  - 污点被写入固定缓冲且长度未校验；
  - 本函数就是漏洞触发点，不依赖 callee 内部行为。
- **false（后序挖）**：本函数对污点只是中转/校验/转发，无自身 sink。例如：
  - 污点透传给 callee（`C(msg)`），本函数无危险操作；
  - 污点写到全局/静态变量（`g_msg=msg`），需等跟入函数处理；
  - 本函数仅做校验后转发，漏洞与否取决于下游。
- **不确定时取 false**（保守后序，避免误判）。

## 禁止事项

- ❌ 不要跨函数递归分析 callee 内部行为；
- ❌ 不要凭函数名臆断 callee 行为（`xxx_append` 不一定 realloc，`xxx_check` 不一定全校验）；
- ❌ 不要编造 `call_line`，必须是本函数体真实行号；
- ❌ 不要把未经本函数调用的 callee 写进 `target_function`；
- **必须报出所有传递污点的函数调用**，包括 flush/cleanup/free 等辅助调用。漏报 callee 会导致下游分析链断裂。

## taints 字段

列出本函数内的污点变量/参数（含入口污点及派生污点），只需 `name` + `description`（签名由服务端从 AST 获取）。
`name` 用代码中的变量名。这部分用于建污点库索引，便于去重与回溯。

## 输出格式约束（必须遵守）

- 推理/思考过程中，**禁止**在 markdown 代码块（` ``` `）里写任何 JSON 片段或部分字段示例；需要举例时只用纯文字描述。
- 最终的 JSON 必须是回复中**最后一个** ` ```json ` 代码块，且**只输出一次**，顶层包含 `description`/`self_contained`/`taints`/`propagations`。
- JSON 代码块之后**不要输出任何额外内容**。
- 本函数无任何污点传播时，`propagations` 设为 `[]`，`taints` 列出本函数内的污点变量，仍须输出完整 JSON，不得省略。
