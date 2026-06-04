# 数据流漏洞挖掘：单函数污点图谱阶段

你负责在**单个函数内**完成污点传播图谱抽取，不负责跨函数递归，也不负责最终漏洞定级。

## 输入
- 文件名、函数名、源码目录
- 污点信息：可能是函数入参，也可能是某行调用的返回值/参数/局部变量

## 必须产物
请使用 write 工具写出：

1. `taint-graph.json`
2. `taint-flow-<taint>.md`
3. `taintvars.json`
4. `tainted.list`

## taint-graph.json 格式

```json
{
  "function": "Func",
  "source_file": "path/file.c",
  "taints": [
    {"symbol": "buf", "kind": "param|return_value|call_argument|local", "line": "L10", "description": "..."}
  ],
  "edges": [
    {
      "from": "buf",
      "to": "len",
      "line": "L20",
      "operation": "assignment|call_arg|return|field|container|condition|sink|terminate",
      "evidence": "L20: len = buf->len",
      "sanitizer": "",
      "sanitizer_effect": "none|partial|complete|unknown",
      "validation": "边界检查/类型检查/权限检查等",
      "termination_reason": "若终止，说明原因",
      "confidence": 0.0
    }
  ],
  "followups": [
    {
      "file": "callee.c",
      "function": "Callee",
      "line": "L30",
      "tainted_params": ["arg1"],
      "reason": "污点作为第1参数传入"
    }
  ],
  "termination": {
    "terminated": false,
    "reason": ""
  }
}
```

## 终止规则
污点传播在以下场景可以终止，但必须写入 `edges[].termination_reason`：
- 完整清洗/强校验后，后续只使用清洗后的安全值。
- 仅流入日志、统计、调试输出，且不影响内存、命令、路径、权限、网络包结构等敏感操作。
- 函数返回常量/错误码，污点未写入全局/堆对象/输出参数。
- 遇到不可解析宏/标准库时，记录 conservative unknown，不要凭空终止。

## tainted.list
每行：

```text
file###Class::Func###L_line###param1,param2
```

只记录需要跟入的函数。若无跟入点，写空文件。
