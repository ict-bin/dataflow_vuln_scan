# 编排库 (orchestration.db) 详细用法

## 数据库结构

| 字段 | 说明 |
|------|------|
| edge_id | 编排边唯一 ID |
| path_id | DFS 路径 ID |
| source_function / target_function | 源/目标函数名 |
| source_func_id / target_func_id | 源/目标函数 ID |
| taint_params | 污点参数 (JSON) |
| depth | 调用深度 |
| edge_order | 路径内顺序 |
| status | 状态 (done/skipped/...) |

## 查询命令

```bash
v2_db orchestration <函数名>
```

输出: 该函数的所有调用链边 (路径, 深度, 顺序, 目标函数, 状态)。
