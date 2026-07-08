---
name: v2-database
description: >
  V2 数据流漏洞扫描数据库查询 bash 命令。查询函数库(functions.db)、污点库(taints.db)、
  传播库(propagations.db)、编排库(orchestration.db), 以及索引新文件建库。
  USE FOR: 查函数源码, 查污点变量, 查传播路径, 查调用链, 索引新文件。
  DO NOT USE FOR: grep 搜索整个源码树, 直接 cat/read 源文件找函数。
metadata:
  author: secflow
  version: "1.0.0"
---

# V2 数据库使用技能

## 核心原则

**禁止 grep 搜索整个源码树。** 所有函数信息已在数据库中, 通过 **bash 命令** `v2_db` 查询。

**`v2_db` 是 bash 命令, 不是 pi 内置工具。** 必须用 `bash` 工具执行, 不能用 `tool_use` 调用。

## 命令路径

```bash
python3 /opt/dataflow_vuln_scan/tools/v2_db.py <命令> <参数>
```

环境变量 `DVS_V2_DB_DIR` 和 `DVS_SOURCE_ROOT` 已由系统设置, 无需手动指定。

## 命令一览

| 命令 | 用途 | 示例 |
|------|------|------|
| `lookup <函数名>` | 查函数库→返回函数体源码 | `bash$ python3 /opt/dataflow_vuln_scan/tools/v2_db.py lookup xmlC14NExecute` |
| `taints <函数名>` | 查污点库→返回函数的污点变量 | `bash$ python3 /opt/dataflow_vuln_scan/tools/v2_db.py taints xmlC14NExecute` |
| `propagations <函数名>` | 查传播库→返回函数的传播路径 | `bash$ python3 /opt/dataflow_vuln_scan/tools/v2_db.py propagations xmlC14NExecute` |
| `orchestration <函数名>` | 查编排库→返回调用链 | `bash$ python3 /opt/dataflow_vuln_scan/tools/v2_db.py orchestration xmlC14NExecute` |
| `index <文件路径>` | 索引新文件到函数库 | `bash$ python3 /opt/dataflow_vuln_scan/tools/v2_db.py index xpath/xpath.c` |
| `symbol <符号名>` | 查宏定义/typedef/struct/enum (grep 全盘 .h/.c) | `bash$ python3 /opt/dataflow_vuln_scan/tools/v2_db.py symbol DNS_MAX_CNAME_LEN` |

## 使用流程

### 需要函数源码时

1. 用 bash 执行 `python3 /opt/dataflow_vuln_scan/tools/v2_db.py lookup <函数名>` → 返回函数体
2. 如果返回 `NOT_FOUND` → 用 `python3 /opt/dataflow_vuln_scan/tools/v2_db.py index <文件路径>` 索引该文件
3. 索引后重新 lookup

### 需要污点/传播/调用链信息时

- `python3 /opt/dataflow_vuln_scan/tools/v2_db.py taints <函数名>` → 污点变量列表
- `python3 /opt/dataflow_vuln_scan/tools/v2_db.py propagations <函数名>` → 传播路径
- `python3 /opt/dataflow_vuln_scan/tools/v2_db.py orchestration <函数名>` → DFS 调用链

## 重要说明

- 函数名支持短名匹配: `ReadDataTask` 可匹配 `Class::ReadDataTask`
- `lookup` 返回的函数体从**原源文件**按 start_line/end_line 读取, 不是缓存副本
- `index` 使用 tree-sitter 精确解析, 无 tree-sitter 时降级为正则提取
- 禁止用 `grep -rn` / `find` 搜索源码树, 一切查询走 bash 命令 `python3 /opt/dataflow_vuln_scan/tools/v2_db.py`

## 各数据库详细用法

参见子技能文档 (需要深入了解时用 read 加载):
- [函数库](sub-skills/functions-db.md)
- [污点库](sub-skills/taints-db.md)
- [传播库](sub-skills/propagations-db.md)
- [编排库](sub-skills/orchestration-db.md)
- [新文件建库](sub-skills/index-new-file.md)
