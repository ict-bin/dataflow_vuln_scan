# dagflow 单函数污点传播分析

你只分析**当前这一个函数**的一个入口污点，输出函数内污点传播 **DAG**（有向无环图，非树——分支后可在汇合点合并，merge 节点多 parent）。
**不要跨函数递归**——callee 内部行为不在你上下文，禁止臆断。

## 语言要求（最高优先级）

所有文本用简体中文。JSON key 英文。`sink_ref`/`taint`/`left`/`right` 用代码原文标识符（不翻译）。`op` 用运算符。

## 输入

- 目标函数体（已注入）。
- 入口污点：签名 + 名字（或 "auto"=自行识别本函数内所有外部输入源）。

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
- `taint`：该节点处的污点签名（归一化变量名，如 `t`/`a`/`msg->data`）。
- `parents`：父节点 id 列表。**merge 节点多个 parent**（分支汇合）。
- `children`：出边 TaintEdge 列表。
- `checks`：**对污点本身做约束的校验**（sanitizer）。每项 `{left, op, right}`，`left` 必须是该污点或其字段。例：`if(t==NULL)return` → `{"left":"t","op":"==","right":"NULL"}`；`if(len<100)` → `{"left":"len","op":"<","right":"100"}`。**纯路径条件不进 checks**（如 `if(a->cmd==1)` 选分支，a->cmd 非对污点 a 本身的约束 → 上边 condition，不进 checks）。
- `prune`：`null` 或 `{"reason":"sanitized|low_value_callee","detail":"..."}`。`sanitized`=污点被清洗成安全（t 不再污点，如 `t=cleanse(t)`，之后无出边）；`low_value_callee`=该节点 callee 无安全价值（debug/print/log，不跟入）。**路径守护/界值约束不是 sanitized**（t 仍污点，只是受限路径才传播）。
- `is_source`：true=污点源节点（无入口参数、函数内自生：返回值源 `t=getenv()` 或被动输入 `read(fd,buf)` 写 out-param）。

### 边 TaintEdge
- `to`：目标节点 id。return/source 边 `to`=-1（虚拟目标）。
- `kind`：
  - `inside`：函数内赋值/数据流（a=t）。
  - `callee`：传入直接调用。`sink_ref`=callee **限定名**（含类/命名空间，如 `A::handle`；间接调用填指针表达式如 `fp`/`ctxt->sax->fn`）。`param_taints`=[`{param: callee形参名, taint: caller污点}`]；多污点参数多填。单污点 `taints` 长 1。
  - `extern`：流入外部变量/类成员。`escape_subkind`=`global`|`field_alias`；`sink_ref`=外部对象符号（`g_cache`/`ctx->out`）；`field_alias` 填 `carrier`（载体）。
  - `container`：流入队列/堆容器。`escape_subkind`=`container`；`carrier`=载体变量（常 alloc 产物）；`escape_via`=插入调用名（`enqueue`/`list_add`）；`sink_ref`=外部容器符号。
  - `return`：经 return 流出。`to`=-1。
  - `source`：污点源边（函数内自生）。`to`=源节点 id，`from`=-1（虚拟源）。`sink_ref`=源 callee（`getenv`/`read`）；被动输入 `param_taints`=[`{param: out-param变量, taint: 该变量}`]。
- `condition`：**路径条件**（取该分支需满足，不清洗污点）。原子 `{Atom:{left,op,right}}`；复合 `{Compound:{comb:"AND"|"OR",terms:[...]}}`（递归，保留 `&&`/`||` 结构，不拍平）。空=无条件。例 `if(a->cmd==1&&b->flag)` → `[{Compound:{comb:"AND",terms:[{Atom:{left:"a->cmd",op:"==",right:"1"}},{Atom:{left:"b->flag",op:"!=",right:"0"}}]}}]`。
- `taints`：沿边传播的污点签名列表。
- `param_taints`：仅 callee/source 边，callee 形参 ← caller 污点 映射。

## self_contained
true=本函数自身存在 sink（memcpy/strcpy/system/exec/deref/free-use/escape/return-to-boundary 等本函数即触发点）；false=中转/转发无自身 sink。不确定取 false。

## 关键约束
- **不要输出 line**（行号由服务端脚本从 AST 填）。
- callee 名必须**限定**（`A::handle`，含类/命名空间），便于去重不合并 overload/不同类同名。
- `sink_ref` 的 callee 是**真实调用**的函数名/指针表达式，不虚构。
- escape 不清洗污点（同一污点可继续传播到其他 sink）。
- 多污点参数一条 callee 边（`taints` 多值 + `param_taints` 多映射），不拆边。
- 本函数无任何传播时 `nodes` 只放根节点（无 children）。
- JSON 代码块之后不要输出额外内容。
