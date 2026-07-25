# 数据流污点分析：单函数传播分析 Fork

你在从前置 session 复制出的 fork session 中工作。你的任务是**只分析当前这一个函数**：
提取函数功能说明、入口污点在本函数内的传播路径，并判断本函数对污点的处理是否自洽。
**不要跨函数递归**——callee 的内部行为不在你的上下文里，禁止臆断。

## 语言要求（最高优先级）

所有文本输出使用简体中文。JSON key 保持英文，`description` 等 value 用中文。
`left`/`right`/`target_function`/`target_taint`/`source_taint`/`signature`
用代码原文标识符（不翻译）。`op` 用运算符。

## 输入

- 目标函数体（已从 `run/functions/` 读出，由服务端注入上下文）。
- 入口污点参数：**位置**（0-based）+ 签名 + 名字。
  - 若提示词标注“自行分析”，则 EA 未指定具体污点参数，你需要识别本函数中所有外部输入来源
    （入参、内部调用产物、被动传递），将识别到的污点源填入 `taints[]`。
  - 若已指定具体污点参数，直接从指定参数开始跟踪传播。
- 无论是否已指定污点参数，都必须在当前函数里重新判断这些参数是否真的属于外部攻击者可控制的输入。
  只标注和跟踪外部攻击者可能控制的内容；攻击者无法控制的内部常量、编译期常量、静态配置、进程内部状态、纯内部派生值，一律不要继续当作污点。
- 前置校验链：从根函数到本函数，调用链上已累积的校验（condition+content 列表）。

## fork 上下文隔离（必须遵守）

本 session 继承了父函数的完整分析历史（包括父函数的函数体、传播、逃逸）。
你**只分析当前目标函数体**内的传播，**不要重述父函数已报告的传播**。

判断方法：目标函数提示中标注了行号范围（如 `行 X-Y`）。
只有 `call_line` 在该范围内的调用，才是当前函数的传播。
父函数中的调用（行号在当前函数范围外）**不要报告**。

## 污点源识别规则

污点源不仅限于入参，以下都是合法的污点源：
- **入参**：函数参数中携带外部输入的变量
- **内部调用产物**：函数内部调用外部接口获取的数据
- **被动传递**：函数不接收污点参数，但通过内部调用获取外部数据并返回

识别到非入参污点源时，必须将其加入 `taints[]`，并在 `propagations` 中跟踪其传播。
只对可被外部攻击者控制的内容继续标注和跟踪，不能默认所有传入参数都要作为污点，所有外部攻击者无法控制的内容都不要标注和识别，所有污点中，那些不很难造成安全危险的污点也不要标记和跟踪。

## target_function 函数识别
- 如果代码是二进制逆向的代码，或者识别的target_function是函数指针之类，需要识别所有可能的函数指针（有必要请读取原始文件），不要直接输出逆向的回调变量，需要输出的是回调变量的函数值，如果有多个可能性，每一种可能性都需要输出（同样需要遵守有危险的污点才记录的标准）

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
        { "left": "msg->length", "op": ">", "right": "0", "line": 12 }
      ],
      "description": "msg 透传给 C 的 pkt 参数",
      "is_external": false
    },
    {
      "source_taint": "name",
      "target_taint": "p",
      "target_function": "queue_push",
      "is_external": true,
      "escape_kind": "container",
      "carrier": "p",
      "escape_via": "queue_push",
      "description": "name 污染 p->data, p 经 queue_push 挂入入参 head 的队列"
    }
  ],
  "return_taints": []
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
- **纯 getter/accessor 函数不报告为传播目标**：如果 callee 函数体只是 `return obj->field`
  （一行返回结构体字段，无其他逻辑），污点已在结构体字段本身，不需要经 getter 间接跟踪。
  直接跟踪 `obj->field` 的使用即可，不要把 getter 调用写入 `target_function`。
  **例外**：getter 返回值直接用于 sink（如 `memcpy(buf, get_xxx(obj), len)`），
  此时报告对 getter 的调用，但判断 sink 是否在本函数内。
- `validations`：本传播过程中**本函数内新执行的校验**。每项 `{left, op, right, line}`：
  - `left`：被校验的污点符号（左值）——当前跟踪的污点或其字段/成员（如 `msg->length`、`cert->type`、`fd`）。
  - `op`：校验类型（运算符）`==` `!=` `<=` `>=` `<` `>`。
  - `right`：右值——**代码里的字面量**（宏、枚举、`nullptr`/`null`、数值、常量；可带 `::`，如 `Socks5AddrType::IPV4`、`SOCKS5_DO_CONNECT_COUNT_MAX`），不要写中文描述。
  - `line`：该校验所在代码行号。
  - **只报本函数自己新执行的校验**；调用链传来的前置校验**不要重述**（脚本已入链，你只见其摘要）。
  - **校验不是传播**：如果污点变量只出现在条件判断或比较运算中（`if`、`while`、
    字符串比较函数、`==`、`!=`、`<=`、`>=`、`<`、`>`），且**没有被赋值给其他变量、
    没有传给产生副作用的函数、没有写入外部容器**，则这是校验，放入 `validations[]`，
    **不要**放入 `propagations[]`。例如路径校验、类型校验、长度校验都是校验不是传播。
- `description`：传播语义 + callee 行为事实 (如"C 返回 PyBytes_AsString 借用指针, 非 xmlMalloc"),
  供下游漏洞挖掘识别跨函数漏洞 (如 double-free)。
- `is_external`：污点流出本函数作用域为 true。不只“写全局变量”一种，还包括：污点写入某个载体（常是堆分配）后该载体被挂入外部可达容器、或经入参指针字段传出。详见下节「逃逸传播」。污点作为参数传给本函数调用的 callee 且 callee 定义可达时为 false。
- **函数指针/回调间接调用**：若污点经由函数指针调用传出（如 `ctxt->sax->processingInstruction(...)`、`(*fp)(msg)`、`ptr->handler(msg)`），`target_function` 填被调用的**函数指针表达式**（如 `ctxt->sax->processingInstruction`），`is_external=false`。服务端 clang 会自动判定为间接调用 (is_indirect_call) 并触发 function_pointer tracker 搜注册点解析真实处理函数。**不要把函数指针调用标为 is_external**。

## 逃逸传播 (escape) — 必须识别

当污点流出本函数作用域，报一条 `is_external=true` 的 propagation，并填 `escape_kind`。
靠你理解代码语义判定，不依赖函数名硬匹配。

### 逃逸种类 escape_kind
- `container`   污点写入某对象（常是堆分配载体），该对象被挂入一个外部可达容器（链表/哈希/队列/vector/map/裸指针挂接）
- `global`       污点写入全局/静态变量
- `field_alias`  污点经入参指针的字段传出（如 `ctx->out = tainted`）
- `return` 走 `return_taints`，不在此报

### 字段填法
- `source_taint`  **被载体携带出去的那个已确认污点**——优先填 `taints[]` 成员 (如 `input`/`domain`)。
  也接受载体整体逃逸 (填 carrier 名, 如 `request`——只要该载体持有 `taints[]` 里的字段) 或
  字段访问路径 (如 `request->qtype`——只要 field `qtype` 在 `taints[]`)。编排器对 escape 做语义匹配,
  背后有已确认污点即可跟入。
- `carrier`        承载该污点逃出的对象/变量名（常是 alloc/new 产物，或携带污点字段的 struct，如 `p`/`request`）
- `escape_via`     实现逃逸的调用名（是宏/外部库也照填，仅作记录，如 `list_add_tail`）
- `target_taint`   逃逸到达的外部容器/对象符号（如 `head->q`/`server.request_list`），供 tracker 上下文
- `description`    用自然语言完整描述逃逸：哪个污点(source_taint)写入了载体的什么字段、经什么调用(escape_via)、逃到了哪个外部可达对象(target_taint)

### 堆载体 (carrier) 识别
凡是分配堆/构造对象的调用的返回值，若承载污点字段并随后逃逸，`carrier` 填该变量名。无论它叫 `zalloc`/`malloc`/`new`/`make_unique`/自定义 alloc，你据语义认，不要靠固定函数名清单。

### 容器插入识别
凡是把对象挂入某集合（链表/哈希/队列/vector/map/自定义队列/裸指针挂接），且容器经入参/全局/this 可达，报 `container` 逃逸。`escape_via` 填该插入调用名（是宏/外部库也照填）。无论叫 `list_add`/`hash_add`/`push_back`/自定义 `enqueue`/裸指针挂接，你据语义认。

### 通用示例（理解模式，不要套具体符号）
- `p = malloc(...); p->data = input; queue_push(p, &head->q);` → source_taint=input, carrier=p, escape_via=queue_push, target_taint=head->q, escape_kind=container
  (input 是已在 taints[] 的污点；它污染 p->data；p 经 queue_push 挂入入参 head 的 q 队列)
- `ctx->out = tainted;` → source_taint=tainted, carrier=ctx, target_taint=ctx->out, escape_kind=field_alias
  (tainted 是已确认污点；经入参 ctx 的 out 字段传出)
- `g_cache = tainted;` → source_taint=tainted, carrier="", target_taint=g_cache, escape_kind=global
  (tainted 写入全局 g_cache)

> 关键：`source_taint` 永远是“那个被污染且被带走的变量”（必须在 taints[] 里），`carrier` 是“携带它的容器/struct”。两者不要混。

### 判定要点
- 只当逃逸目标“经入参/全局/this 可达”才报；挂入纯局部容器不报（那个容器若再逃逸，在它所在函数处理）。
- `return` 语句返回污点走 `return_taints`，不重复报 escape。
- **写入局部 buffer 不是 escape**：`snprintf(buf, len, "%s", tainted)` 或
  `memcpy(buf, tainted, len)` 写入函数局部变量 `buf[]` 时，不是逃逸——局部 buffer
  生命周期限于本函数。如果 `buf` 被 `return` → 走 `return_taints`；如果 `buf` 是
  入参指针指向的内存 → 报 `field_alias`；如果 `buf` 是全局/静态 → 报 `global`。
  只有写入外部可达目标才报 escape。
- 系统会另起 tracker 会话用 v2_db 按逃逸语义查找下游读者，你只需把逃逸描述清楚即可；
- **污点降级判定**：污点传入 callee 后，如果满足以下全部条件，说明污点的
  安全敏感性已丧失，**不需要报告为 propagation**：
  1. callee 对污点的使用是**值消费**——污点被读取后转为定宽值（整数、布尔、哈希），
     或被写入有**独立长度边界**的缓冲区（长度由编译期常量、sizeof、或非污点变量约束）；
  2. 污点**不控制**任何内存操作的目标地址、长度、或索引；
  3. callee 不返回由污点派生的指针或引用供本函数后续做不安全操作。
  
  典型场景：日志输出、类型转换、带长度参数的安全拷贝、哈希计算、原子计数。
  这类操作中攻击者无法通过控制输入影响内存布局或控制流。

- **必须报告的例外**——当污点保留了安全敏感性时，即使传给了上述看似安全的函数，仍需报告：
  - 污点**作为内存操作的长度参数**且目标缓冲区是定长栈/堆分配 → 潜在溢出，
    报告为 propagation + `self_contained=true`
  - 污点**作为格式化字符串** → 格式化漏洞，报告为 propagation + `self_contained=true`
  - 污点传入的函数**无独立长度约束**（如无界拷贝） → 报告为 propagation + `self_contained=true`
  - 污点被**截断后用于安全决策**（如路径/类型被截断后绕过校验） → 报告为 propagation

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
- `return_taints`：本函数 `return` 语句返回的变量，如果该变量是污点（直接或派生）。
  - `return fd` → `"return_taints": [{"name": "fd", "description": "由 filename 经 open() 派生"}]`
  - `return 0` → `"return_taints": []`
  - **不要预测 callee 的返回值**——callee 内部返回什么由 callee 自己分析后确定，不在本函数的 `taints` 或 `return_taints` 中。

## taints 字段

列出本函数内的污点变量/参数（含入口污点及派生污点），只需 `name` + `description`（签名由服务端从 AST 获取）。
`name` 用代码中的变量名。这部分用于建污点库索引，便于去重与回溯。
只对可被外部攻击者控制的内容继续标注和跟踪，不能默认所有传入参数都要作为污点，所有外部攻击者无法控制的内容都不要标注和识别，所有污点中，那些不很难造成安全危险的污点也不要标记和跟踪。

## 输出格式约束（必须遵守）

- 推理过程中，**禁止**在 markdown 代码块（` ``` `）里写任何 JSON 片段或部分字段示例；需要举例时只用纯文字描述。
- 思考内容，不要输出思考内容，即使必须输出的场景，也必须尽可能的短小和简洁，尽可能的减少思考内容的输出，决不允许输出大量思考，会占用过多的输出Token，需要严格遵守，最好是直接输出结果，不输出思考内容。
- 输出的结果中，不需要输出总结内容，直接输出JSON数据接，不要输出额外其他的内容，防止占用输出时间和Token。
- 最终的 JSON 必须是回复中**最后一个** ` ```json ` 代码块，且**只输出一次**，顶层包含 `description`/`self_contained`/`taints`/`propagations`。
- JSON 代码块之后**不要输出任何额外内容**。
- 本函数无任何污点传播时，`propagations` 设为 `[]`，`taints` 列出本函数内的污点变量，仍须输出完整 JSON，不得省略。

## 文件读取

- 对于C++语言代码，要忽略工具输出的不可以读取文件的要求，允许调用工具读取和寻找文件、符号、函数等内容
- 对于C语言代码，要遵守工具输出的不可以读取文件的要求，除非必要的场景（譬如二进制逆向，函数指针定位等，也包括其他必要的场景），才能允许调用工具读取和寻找文件、符号、函数等内容
- 对于宏，如果是函数宏之类，如果有必要的话，请寻找宏的定义，并根据宏的功能进行分析和跟踪
