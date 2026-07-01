---
name: v2-database
description: >
  V2 数据流漏洞扫描数据库使用工具。查询函数库(functions.db)、污点库(taints.db)、
  传播库(propagations.db)、编排库(orchestration.db), 以及索引新文件建库。
  USE FOR: 查函数源码, 查污点变量, 查传播路径, 查调用链, 索引新文件。
  DO NOT USE FOR: grep 搜索整个源码树, 直接 cat/read 源文件找函数。
metadata:
  author: secflow
  version: "1.0.0"
---

# V2 数据库使用技能

## 核心原则

**禁止 grep 搜索整个源码树。** 所有函数信息已在数据库中, 通过 `v2_db` 工具查询。

## 工具路径

```bash
python3 /opt/dataflow_vuln_scan/tools/v2_db.py <命令> <参数>
```

环境变量 `DVS_V2_DB_DIR` 和 `DVS_SOURCE_ROOT` 已由系统设置, 无需手动指定。

## 命令一览

| 命令 | 用途 | 示例 |
|------|------|------|
| `lookup <函数名>` | 查函数库→返回函数体源码 | `v2_db lookup xmlC14NExecute` |
| `taints <函数名>` | 查污点库→返回函数的污点变量 | `v2_db taints xmlC14NExecute` |
| `propagations <函数名>` | 查传播库→返回函数的传播路径 | `v2_db propagations xmlC14NExecute` |
| `orchestration <函数名>` | 查编排库→返回调用链 | `v2_db orchestration xmlC14NExecute` |
| `index <文件路径>` | 索引新文件到函数库 | `v2_db index xpath/xpath.c` |

## 使用流程

### 需要函数源码时

1. `v2_db lookup <函数名>` → 返回函数体 (从原源文件按行读取)
2. 如果返回 `NOT_FOUND` → 用 `v2_db index <文件路径>` 索引该文件
3. 索引后重新 `v2_db lookup <函数名>`

### 需要污点/传播/调用链信息时

- `v2_db taints <函数名>` → 污点变量列表
- `v2_db propagations <函数名>` → 传播路径 (source→target, 行号, 条件)
- `v2_db orchestration <函数名>` → DFS 调用链 (路径, 深度, 目标函数)

## 重要说明

- 函数名支持短名匹配: `ReadDataTask` 可匹配 `Class::ReadDataTask`
- `lookup` 返回的函数体从**原源文件**按 start_line/end_line 读取, 不是缓存副本
- `index` 使用 tree-sitter 精确解析, 无 tree-sitter 时降级为正则提取
- 禁止用 `grep -rn` / `find` 搜索源码树, 一切查询走 `v2_db`

## 各数据库详细用法

参见子技能文档 (需要深入了解时用 read 加载):
- [函数库](sub-skills/functions-db.md)
- [污点库](sub-skills/taints-db.md)
- [传播库](sub-skills/propagations-db.md)
- [编排库](sub-skills/orchestration-db.md)
- [新文件建库](sub-skills/index-new-file.md)
