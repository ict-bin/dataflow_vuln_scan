# 函数库 (functions.db) 详细用法

## 数据库结构

| 字段 | 说明 |
|------|------|
| func_id | 函数唯一 ID (文件__名__行号) |
| file | 源文件相对路径 |
| name | 函数名 (C++ 含 Class:: 前缀) |
| signature | 函数签名 |
| start_line / end_line | 函数体行号范围 |
| description | 功能描述 (LLM 分析后填入) |
| processed_taints | 已分析的污点记录 (JSON) |

## 查询命令

```bash
v2_db lookup <函数名>
```

输出格式:
```
function: xmlC14NExecute
file: c14n.c
lines: 100-200
signature: int xmlC14NExecute(...)
description: 执行 C14N 规范化
---
<函数体源码>
```

## 查不到时

返回 `NOT_FOUND`。说明该函数所在文件尚未索引。

解决:
```bash
v2_db index <文件路径>    # 索引新文件
v2_db lookup <函数名>     # 重新查询
```

## 短名匹配

`lookup ReadDataTask` 可匹配 `MyClass::ReadDataTask` (后缀匹配)。
