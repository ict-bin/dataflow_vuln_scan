# dagflow 单函数污点传播分析

你只分析**当前这一个函数**的一个入口污点，输出函数内污点传播 **DAG**（有向无环图，非树——分支后可在汇合点合并，merge 节点多 parent）。
**不要跨函数递归**——callee 内部行为不在你上下文，禁止臆断。

:## 工具约束（防 session 膨胀，必须遵守）

- **函数体已在上方 prompt 提供（带行号），不要用 `read` 重读本函数**（重读会爆 session 内存）。
- **查 callee 签名/宏定义/符号 → 走 v2_db**（返回 bounded 结果，快）:
  - `python3 /opt/dataflow_vuln_scan/tools/v2_db.py lookup <函数名>` — 返回函数体（带行号）
  - `python3 /opt/dataflow_vuln_scan/tools/v2_db.py symbol <符号名>` — 返回宏/struct/typedef 定义
- **不要用 `grep`/`find` 搜源码树** — grep -rn 返回大量结果行导致 session 膨胀，后续每轮 LLM 调用 input token 越来越大，最终超时。v2_db 只返回你需要的函数体，不会有这个问题。
- **工具调用总预算: 最多 5 次**。函数体已在 prompt 中，v2_db 只用于查 callee 签名。超过 5 次说明你在过度搜索。

## callee 边规则（核心，易漏）

**函数内任何携带污点的变量被作为参数传给另一个函数 = callee 边。** 不管该变量是入口污点本身，还是从入口污点传播来的中间变量。只要被污染的变量出现在函数调用实参中，就必须发 callee 边，`tainted_args` 记录被污实参索引。

漏发 callee 边会导致下游函数的该污点路径不被跟踪，相关漏洞漏报。
- **不需要额外搜索**：本函数体 + v2_db 足够产出 DAG。只在 callee 是用户函数且需确认其签名时查 v2_db。

## 行号是沟通桥梁（核心规则）

- prompt 中的函数体**每行已标记行号**（如 `765│ code...`）。
- 你输出 DAG 时**用行号引用**代码位置，不要输出结构化的条件/校验对象。
- 脚本会从你输出的行号读源码解析出条件文本、校验文本、调用参数等结构化数据。
- **行号必须是 prompt 中标记的行号**（文件绝对行号，不是相对行号）。
- **跨行场景**（多行 if 条件、多行调用）：输出行号范围 `[起始行, 结束行]`。

## 入口污点定位（必做）

入口污点签名 X（已给）。**先在本函数定位 X 的真实入口**：
- X 是本函数参数？→ 根节点 `line`=该参数声明行，`source`=null。
- X 是本函数内自生（返回值源 / 被动输入）？→ 节点 `source`=该调用名，`line`=该调用行。
- **X 不是本函数参数、也不是函数内外部输入源？→ `taint_failed=true`，description 说明"X 非有效污点源"，nodes 只放根节点，edges 为空数组。**

## source 识别（必须检查，漏报导致 tracker 不跑）

任何从外部（网络/文件/环境/IPC）获取数据的调用，其输出变量是污点源：
- 网络接收调用（recv/recvmsg/read 等）的输出 buffer → 节点 `source`=该调用名。
- 返回外部数据的调用（getenv/fgets 等）的返回值 → 节点 `source`=该调用名。
- **系统接口返回值（时间戳/tick/PID 等）不是污点源**——这些非攻击者可控。
- **宁可多报不可漏报**：任何从外部获取数据的调用都是 source。

## escape / indirect 识别（必须检查）

### escape 边（extern/container）
污点**跨越到不同的作用域**才算 escape——不是在同一个入参的嵌套结构内传播：
- 污点赋给**全局/静态变量** → `kind=extern`，`carrier`=该全局变量名。
- 污点写入**入参指针的字段** → `kind=extern`，`carrier`=入参对象.字段路径。“入参”指函数签名声明的参数本身，不是从参数字段派生的局部变量。
- 污点写入**堆对象后挂入容器**（链表/队列等）→ `kind=container`，`carrier`=载体变量，`escape_via`=插入调用名。

**以下情况不是 escape，是 inside：**
- 局部指针变量从入参字段获取（读取入参的嵌套指针后赋给局部变量），写该局部变量的字段是 inside。因为该局部变量是入参嵌套结构的别名，污点仍留在入参作用域内，未跨越到其他作用域。
- 判定标准：被写入的对象是函数签名声明的入参吗？是 → escape。是局部变量（即使它指向入参的嵌套内存）→ inside。

### indirect 调用
经函数指针/回调/dispatch 调用：
- `(*fp)(t)` / `obj->handler(t)` → `kind=callee`，`callee`=**指针表达式**（非函数名）。tracker 会解析真实函数。

## 必须输出 JSON（顶层唯一一个 ```json 块，最后输出）

**nodes 和 edges 是两个独立的顶层数组**。先列所有节点，再列所有边。每条边必须有 `from` 和 `to`（节点数组下标，0-based）。

```json
{
  "description": "本函数功能（一句话）",
  "self_contained": false,
  "taint_failed": false,
  "nodes": [
    {"taint": "events", "line": 765, "source": "epoll_wait", "check_lines": [786, [746, 748]]},
    {"taint": "event", "line": 776, "source": null},
    {"taint": "conn_head", "line": 796, "source": null},
    {"taint": "conn->last_request_time", "line": 480, "source": null}
  ],
  "edges": [
    {"from": 0, "to": 1, "kind": "inside", "taints": ["event"], "line": 776},
    {"from": 1, "to": 2, "kind": "callee", "callee": "_dns_server_process",
     "taints": ["event"], "line": 796,
     "tainted_args": [{"i": 1, "taint": "event"}, {"i": 2, "taint": "now"}],
     "cond_lines": [786]
    },
    {"from": 1, "to": 3, "kind": "extern", "taints": ["conn->last_request_time"],
     "line": 480, "carrier": "conn->last_request_time",
     "escape_via": "_dns_server_client_touch"
    },
    {"from": 1, "to": -1, "kind": "return", "line": 850}
  ],
  "prunes": {"0": "low_value_callee"}
}
```

### 节点字段（nodes 数组的每一项）
- `taint`：该节点处的污点签名（归一化变量名）。
- `line`：该节点对应的代码行号。多行时输出 `[起始行, 结束行]`。
- `source`：null=非源节点；"epoll_wait"=源调用名（函数内自生污点）。
- `check_lines`：**对污点本身做约束的校验**行号列表。每个元素是行号(int)或行号范围 `[start, end]`。**纯路径条件不进 check_lines**（选分支的条件上 `cond_lines`）。

### 边字段（edges 数组的每一项）
- `from`：**起始节点在 nodes 数组中的下标**（0-based，不是行号！）。node[0] 是 nodes 数组第一个元素。必填。
- `to`：目标节点在 **nodes 数组中的下标**（0-based，不是行号！）。return 边 `to`=-1。
- `kind`：`inside` | `callee` | `extern` | `container` | `return`。
- `taints`：沿边传播的污点签名列表。**return 边不需要输出 taints**——脚本会从 return 语句行号读源码自动提取返回表达式。
- `line`：传播发生的代码行号。多行时 `[start, end]`。
- `callee`（仅 callee 边）：callee **限定名**（含类/命名空间）；间接调用填指针表达式。
- `tainted_args`（仅 callee 边）：被污的实参索引列表，每项 `{"i": 索引, "taint": 污点签名}`。索引是调用中实参的位置（0-based，从 callee 名后第一个参数开始）。脚本会从源码提取实参表达式并映射到 callee 签名形参名。
- `cond_lines`（可选）：路径条件行号列表。每个元素是行号或 `[start, end]`。指向 if-statement 的行号，脚本从源码提取条件文本。省略或空=无条件。
- `carrier`（仅 extern/container 边）：载体变量名。
- `escape_via`（仅 extern/container 边）：逃逸调用名。

### return 边规则
- C/C++ 函数只有一个返回值。**return 边只需输出 `line`（return 语句行号），不需要输出 `taints`**。
- 脚本会从该行号读源码，提取 `return <表达式>;` 中的返回表达式作为污点名。
- **返回常量（数值/NULL/0/-1）的 return 语句不发 return 边**——无污点传播。
- 只有返回**携带污点的变量或表达式**时才发 return 边。

### prunes
顶层 dict，key=节点下标（字符串），value=原因。
- `sanitized`：污点被清洗成安全（之后无出边）。
- `low_value_callee`：该节点 callee 无安全价值（日志/调试类，不跟入）。
- **路径守护/界值约束不是 sanitized**（taint 仍污点，只是受限路径才传播）。

## self_contained
true=本函数自身存在 sink（危险操作即触发点）；false=中转/转发无自身 sink。不确定取 false。

## 关键约束
- **edges 是顶层独立数组，不是嵌套在 nodes 里**。每条边必须有 `from` 和 `to`。
- **`from` 和 `to` 是 nodes 数组的下标（0, 1, 2...），不是代码行号**。node[0] 是 nodes 数组第一个元素，node[1] 是第二个，以此类推。
- callee 名必须**限定**（含类/命名空间），便于去重不合并 overload。
- `tainted_args` 的 `i` 是实参在**调用表达式中的位置**（0=第一个参数），不是 callee 形参位置。脚本会按位置映射到形参名。
- escape 不清洗污点（同一污点可继续传播到其他 sink）。
- 多污点参数一条 callee 边（`taints` 多值 + `tainted_args` 多项），不拆边。
- return 边不输出 `taints`——脚本从行号提取。
- 本函数无任何污点传播时 `nodes` 只放根节点，`edges` 为空数组。
- JSON 代码块之后不要输出额外内容。
