# dagflow 单函数污点传播分析

你只分析**当前这一个函数**的一个入口污点，输出函数内污点传播**列表**（扁平, 非嵌套）。
**不要跨函数递归**——callee 内部行为不在你上下文，禁止臆断。

## 工具约束（防 session 膨胀，必须遵守）

- **函数体已在上方 prompt 提供（带行号），不要用 `read` 重读本函数**。
- **查 callee 签名/宏定义/符号/调用关系 → 走 v2_db**:
  - `python3 /opt/dataflow_vuln_scan/tools/v2_db.py lookup <函数名>` — 返回函数体
  - `python3 /opt/dataflow_vuln_scan/tools/v2_db.py symbol <符号名>` — 返回宏/struct/typedef 定义
  - `python3 /opt/dataflow_vuln_scan/tools/v2_db.py callee <函数名>` — 查该函数调用了哪些函数
- **不要用 `grep`/`find` 搜源码树** — session 膨胀。v2_db 只返回你需要的函数体。
- **工具调用总预算: 最多 5 次**。

## 行号是沟通桥梁

- prompt 中函数体每行已标记行号（如 `765│ code...`）。
- 你输出传播时用**行号**引用代码位置。
- 脚本从行号读源码解析出条件文本、校验文本、调用参数等。
- **行号必须是 prompt 中标记的行号**（文件绝对行号）。
- 多行场景输出行号范围 `[起始行, 结束行]`。

## 入口污点定位（必做）

入口污点签名 X（已给）。先在本函数定位 X 的真实入口：
- X 是本函数参数？→ 传播的 `from_var` = 该参数名, `from_line` = 声明行。
- X 是本函数内自生？→ 在 `sources` 数组声明, `source_call` = 产生该污点的调用名。
- **X 非参数也非函数内源？→ `taint_failed=true`, propagations 为空数组。**

## source 识别

任何从外部获取数据的调用，其输出变量是污点源：
- 网络接收调用（recv/recvmsg/read 等）的输出 buffer → source。
- 返回外部数据的调用（getenv/fgets 等）的返回值 → source。
- **系统接口返回值（时间戳/PID 等）不是源。**
- **宁可多报不可漏报。**

## callee 边规则

**函数内任何携带污点的变量被作为参数传给另一个函数 = callee 边。** 不管该变量是入口污点本身还是中间变量。
- `callee` = callee 限定名（含类/命名空间）。
- `tainted_args` = 被污实参列表, 每项 `{"i": 实参位置(0-based), "taint": 污点签名}`。
- 间接调用（函数指针/回调）→ `callee` = 指针表达式。

## escape 边规则

污点**跨越到不同作用域**才算 escape：
- 污点赋给**全局/静态变量** → `kind=extern`, `carrier` = 全局变量名。
- 污点写入**入参指针的字段** → `kind=extern`, `carrier` = 入参.字段路径。
- 污点写入**堆对象后挂入容器** → `kind=extern`, `carrier` = 载体变量, `escape_via` = 插入调用名。
- **局部指针别名间传播是 inside, 不是 escape。**

## return 边规则

- 只有返回**携带污点的变量或表达式**时才发 return 边。
- 返回常量（NULL/0/-1）不发 return 边。
- return 边的 `to_var` 留空 `""`, `to_line` = return 语句行号。

## prunes

- `sanitized`: 污点被清洗成安全（之后无传播）。
- `low_value_callee`: 该 callee 无安全价值（日志/调试类）。
- **路径守护/界值约束不是 sanitized**（taint 仍污点, 只是受限路径才传播）。

## 必须输出 JSON（顶层唯一一个 ```json 块, 最后输出）

```json
{
  "description": "本函数功能（一句话）",
  "self_contained": false,
  "taint_failed": false,
  "propagations": [
    {
      "from_var": "events",
      "from_line": 765,
      "to_var": "event",
      "to_line": 776,
      "kind": "inside",
      "check_lines": [786, [746, 748]],
      "cond_lines": [786]
    },
    {
      "from_var": "event",
      "from_line": 776,
      "to_var": "_dns_server_process",
      "to_line": 796,
      "kind": "callee",
      "callee": "_dns_server_process",
      "tainted_args": [{"i": 1, "taint": "event"}],
      "cond_lines": [786]
    },
    {
      "from_var": "event",
      "from_line": 776,
      "to_var": "conn->last_request_time",
      "to_line": 480,
      "kind": "extern",
      "carrier": "conn->last_request_time",
      "escape_via": "_dns_server_client_touch"
    },
    {
      "from_var": "event",
      "from_line": 776,
      "to_var": "",
      "to_line": 850,
      "kind": "return"
    }
  ],
  "sources": [
    {"var": "events", "line": 765, "source_call": "epoll_wait"}
  ],
  "prunes": [
    {"var": "debug_ptr", "reason": "low_value_callee"}
  ]
}
```

### propagation 字段

| 字段 | 说明 |
|------|------|
| `from_var` | 源变量名（污点从哪来） |
| `from_line` | 源变量行号 |
| `to_var` | 目标变量名（污点到哪去）。return 边留空 `""` |
| `to_line` | 目标行号（传播发生的行） |
| `kind` | `inside` \| `callee` \| `extern` \| `return` |
| `callee` | 仅 callee 边: callee 限定名或指针表达式 |
| `tainted_args` | 仅 callee 边: `[{"i": 实参位置, "taint": 污点签名}]` |
| `carrier` | 仅 extern 边: 载体变量名 |
| `escape_via` | 仅 extern 边: 逃逸调用名 |
| `check_lines` | 这段传播上对污点的校验行号 (int 或 [start, end]) |
| `cond_lines` | 分支条件行号 (if-statement 的行号) |

### sources 数组

函数内自生的污点源（非入口参数）:
- `var`: 变量名
- `line`: 行号
- `source_call`: 产生该污点的调用名

### prunes 数组

- `var`: 被剪枝的变量名
- `reason`: `sanitized` \| `low_value_callee`

## self_contained

true=本函数自身存在 sink（危险操作即触发点）；false=中转/转发无自身 sink。

## 关键约束

- **不需要输出 nodes/edges 数组, 不需要下标引用**。只输出 propagations 扁平列表。
- 同一变量被多个源传播时, 输出多条 propagation (脚本自动合并为 merge 节点)。
- `check_lines` 和 `cond_lines` 每个元素是行号(int)或行号范围 `[start, end]`。
- 本函数无任何污点传播时 `propagations` 为空数组, `taint_failed=true`。
- JSON 代码块之后不要输出额外内容。
