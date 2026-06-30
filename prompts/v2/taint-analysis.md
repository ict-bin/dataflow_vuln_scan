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
    { "name": "msg", "signature": "msg_t*", "description": "入口报文指针" }
  ],
  "propagations": [
    {
      "source_taint": "msg",
      "source_signature": "msg_t*",
      "target_taint": "pkt",
      "target_signature": "pkt_t*",
      "target_function": "C",
      "target_file": "net/c.c",
      "call_line": 234,
      "condition": "always",
      "validations": [
        { "condition": "msg->length>0", "content": "长度已校验" }
      ],
      "description": "msg 透传给 C 的 pkt 参数",
      "is_external": false,
      "is_indirect_call": false,
      "dispatch_kind": ""
    }
  ]
}
```

## 字段硬约束（违反即丢弃该 propagation）

- `call_line`：**必须是本函数体内真实存在的行号**（clang 会校验该行确有对 `target_function`
  的 CallExpr；幽灵调用点直接丢弃）。若该传播不是经由函数调用（如写到外部变量），
  `call_line` 填写发生赋值/传播的行号，`target_function` 留空，`is_external=true`。
- `target_function`：必须是本函数**真实调用**的 callee 名（clang 校验）。未在本函数调用的
  callee 不得出现。传播到外部/全局变量时留空 + `is_external=true`。
- `target_file`：callee 所在文件（相对源码根）。不确定时留空，服务端用函数库解析。
- `condition`：人类可读传播条件（如 `"if(x) then"`、`"always"`、`"msg->len>0 守护"`）。
  **仅作辅助说明，不作为分支分叉依据**——分支互斥性由 clang 按调用点 AST 判定。
- `validations`：本传播过程中（从源污点到调用点）累积的校验，每项 `{condition, content}`。
  包括上游传入的前置校验中**在本函数内仍然生效**的部分，以及本函数新增加的校验。
- `is_external`：仅当污点传播到**非函数指针的外部/全局数据变量**（如 `g_msg = msg`、`ctx->user_data = msg` 这类**数据赋值**）时为 true。
  此时编排器会触发 nonlocal 跟踪 LLM 查找读取该变量的跟入函数。
- `is_indirect_call`：当传播是经由**函数指针/回调/dispatch 间接调用**（如 `ctxt->sax->processingInstruction(...)`、
  `(*fp)(msg)`、`ptr->handler(msg)`、`dispatch_table[id](msg)`）时为 true，并填 `dispatch_kind`
  （`function_pointer_field`/`callback`/`vtable`/`dispatch_map`）。此时 `target_function` 填被调用的
  函数指针表达式（如 `ctxt->sax->processingInstruction`）。编排器会触发 function_pointer tracker
  搜索注册点（`sax->processingInstruction = handler` / `register_handler` / init 表）解析真实处理函数。
  **不要把函数指针调用标为 is_external** —— 函数指针字段是动态分派, 不是“持有污点的外部数据变量”。

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
  - 污点写到外部变量（`g_msg=msg`），需等跟入函数 H/I 的处理；
  - 本函数仅做校验后转发，漏洞与否取决于下游。
- **不确定时取 false**（保守后序，避免误判）。

## 禁止事项

- ❌ 不要跨函数递归分析 callee 内部行为（callee 函数体不在你的上下文）；
- ❌ 不要凭函数名臆断 callee 行为（`xxx_append` 不一定 realloc，`xxx_check` 不一定全校验）；
- ❌ 不要编造 `call_line`，必须是本函数体真实行号；
- ❌ 不要把未经本函数调用的 callee 写进 `target_function`；
- ❌ 不要对 `self_contained` 乐观——无明确 sink 即取 false。

## taints 字段

列出本函数内的污点变量/参数（含入口污点及派生污点）。`signature` 用类型或归一化签名。
`name` 用代码中的变量名。这部分用于建污点库索引，便于去重与回溯。
