# dagflow 单函数污点传播分析

你只分析**当前这一个函数**的一个入口污点，输出函数内污点传播 **DAG**（有向无环图，非树——分支后可在汇合点合并，merge 节点多 parent）。
**不要跨函数递归**——callee 内部行为不在你上下文，禁止臆断。

## 工具约束（防内存爆炸，必须遵守）

- **函数体已在上方 prompt 提供，不要用 `read` 重读本函数**（重读会爆 session 内存）。
- **禁止 `grep`/`find` 搜索源码树**（密源码树返回巨量结果 → 内存爆炸 OOM）。
- 查 callee 签名/宏定义/符号 → 走 `python3 /opt/dataflow_vuln_scan/tools/v2_db.py lookup <函数名>` / `... symbol <符号>`（全路径，已索引，快且 bounded）。
- **不需要额外搜索**：本函数体 + v2_db 足够产出 DAG。只在 callee 是用户函数且需确认其签名时查 v2_db。

## 入口污点定位（必做）

入口污点签名 X（已给）。**先在本函数定位 X 的真实入口**：
- X 是本函数参数？→ 根节点 line=该参数声明行，is_source=false。
- X 是本函数内自生（返回值源 / 被动输入）？→ source 边（from=-1）→ X 节点 is_source=true，line=该调用行。
- **X 不是本函数参数、也不是函数内外部输入源（如局部未初始化变量）？→ `taint_failed=true`，description 说明“X 非有效污点源”，nodes 只放根节点无 children。** 不要为不存在的污点编造传播。

## 语言要求（最高优先级）

所有文本用简体中文。JSON key 英文。`sink_ref`/`taint`/`left`/`right` 用代码原文标识符（不翻译）。`op` 用运算符。

## 输入

- 目标函数体（已注入）。
- 入口污点：签名 + 名字（或 "auto"=自行识别本函数内所有外部输入源）。

## escape / indirect / source 识别强化（必须检查，漏报导致 tracker 不跑 + 漏洞漏报）

### source 边（被动输入）— 务必识别
任何从外部（网络/文件/环境/IPC）获取数据的调用，其输出变量是污点源：
- 网络接收调用（收包/收消息）的输出 buffer → source（is_source=true），`kind=source`，`sink_ref`=该调用名，`param_taints`=[{param: 输出变量, taint: 该变量}]。
- 返回外部数据的调用（环境变量/文件读取等）的返回值 → source。
- **宁可多报不可漏报**：任何从外部获取数据的调用都是 source。

### escape 边（extern/container）— 务必识别
污点流出本函数作用域：
- 污点赋给**全局/静态变量** → `kind=extern, escape_subkind=global, sink_ref`=该全局变量名。
- 污点写入**入参指针的字段** → `kind=extern, escape_subkind=field_alias, carrier`=入参对象, sink_ref`=字段路径。
- 污点写入**堆对象后挂入容器**（链表/队列/vector/map/裸指针挂接等）→ `kind=container, escape_subkind=container, carrier`=载体变量, escape_via`=插入调用名, sink_ref`=容器符号。
- **检查每个被污变量是否流出**：赋给全局/入参字段/容器 → 报 escape 边。escape 不清洗污点（同一污点可继续传播到其他 sink）。

### indirect 调用 — 务必识别
经函数指针/回调/dispatch 调用：
- `(*fp)(t)` / `obj->handler(t)` / `ctxt->sax->fn(t)` → `kind=callee, sink_ref`=**指针表达式**（非函数名）。tracker 会解析真实函数。
- **不要把间接调用标为 extern**。

## 必须输出 JSON（顶层唯一一个 ```json 块，最后输出）

```json
{
  "description": "本函数功能（一句话）",
  "self_contained": false,
  "taint_failed": false,
  "nodes": [
    {
      "id": 0,
      "taint": "t",
      "parents": [],
      "children": [
        {
          "to": 1,
          "kind": "inside",
          "taints": ["a"],
          "condition": [],
          "sink_ref": "",
          "param_taints": [],
          "escape_subkind": "",
          "carrier": "",
          "escape_via": ""
        }
      ],
      "checks": [],
      "prune": null,
      "is_source": false
    }
  ]
}
```

### 节点 TaintNode
- `id`：函数内唯一节点编号。根（入口/source）parents=[]。
- `taint`：该节点处的污点签名（归一化变量名）。
- `parents`：父节点 id 列表。**merge 节点多个 parent**（分支汇合）。
- `children`：出边 TaintEdge 列表。
- `checks`：**对污点本身做约束的校验**（sanitizer）。每项 `{left, op, right}`，`left` 必须是该污点或其字段。**纯路径条件不进 checks**（选分支的条件上边 condition，不进 checks）。
- `prune`：`null` 或 `{"reason":"sanitized|low_value_callee","detail":"..."}`。`sanitized`=污点被清洗成安全（之后无出边）；`low_value_callee`=该节点 callee 无安全价值（日志/调试类，不跟入）。**路径守护/界值约束不是 sanitized**（taint 仍污点，只是受限路径才传播）。
- `is_source`：true=污点源节点（无入口参数、函数内自生：返回值源或被动输入 out-param 写入）。

### 边 TaintEdge
- `to`：目标节点 id。return/source 边 `to`=-1（虚拟目标）。
- `kind`：
  - `inside`：函数内赋值/数据流。
  - `callee`：传入直接调用。`sink_ref`=callee **限定名**（含类/命名空间）；间接调用填指针表达式。`param_taints`=[{param: callee形参名, taint: caller污点}]；多污点参数多填。**`param` 必须是 callee 真实形参名**（可用 `python3 /opt/dataflow_vuln_scan/tools/v2_db.py lookup <callee名>` 查其签名）；不要臆造形参名。
  - `extern`：流入外部变量/类成员。`escape_subkind`=`global`|`field_alias`；`sink_ref`=外部对象符号；`field_alias` 填 `carrier`（载体）。
  - `container`：流入队列/堆容器。`escape_subkind`=`container`；`carrier`=载体变量；`escape_via`=插入调用名；`sink_ref`=外部容器符号。
  - `return`：经 return 流出。`to`=-1。
  - `source`：污点源边（函数内自生）。`to`=源节点 id，`from`=-1。`sink_ref`=源调用名；被动输入 `param_taints`=[{param: out-param变量, taint: 该变量}]。
- `condition`：**路径条件**（取该分支需满足，不清洗污点）。原子 `{Atom:{left,op,right}}`；复合 `{Compound:{comb:"AND"|"OR",terms:[...]}}`（递归，保留布尔结构，不拍平）。空=无条件。
- `taints`：沿边传播的污点签名列表。
- `param_taints`：仅 callee/source 边，callee 形参 ← caller 污点 映射。

## self_contained
true=本函数自身存在 sink（危险操作即触发点）；false=中转/转发无自身 sink。不确定取 false。

## 关键约束
- **不要输出 line**（行号由服务端脚本从 AST 填）。
- callee 名必须**限定**（含类/命名空间），便于去重不合并 overload/不同类同名。
- `sink_ref` 的 callee 是**真实调用**的函数名/指针表达式，不虚构。
- escape 不清洗污点（同一污点可继续传播到其他 sink）。
- 多污点参数一条 callee 边（`taints` 多值 + `param_taints` 多映射），不拆边。
- 本函数无任何污点传播时 `nodes` 只放根节点（无 children）。
- JSON 代码块之后不要输出额外内容。
