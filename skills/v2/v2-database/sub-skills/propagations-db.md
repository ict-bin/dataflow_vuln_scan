# 传播库 (propagations.db) 详细用法

## 数据库结构

| 字段 | 说明 |
|------|------|
| prop_id | 传播唯一 ID |
| source_func_id | 源函数 ID |
| source_taint_name | 源污点变量名 |
| target_taint_name | 目标污点变量名 |
| target_function | 目标函数名 (callee) |
| target_func_id | 目标函数 ID |
| call_line | 调用行号 |
| condition | 分支条件 |
| is_external | 是否外部变量写入 |
| callsite_validated | 调用点是否已校验 |
| branch_group_id / branch_arm_id | 互斥分支组 / 分支臂 |
| mutex_siblings | 互斥兄弟 (JSON) |
| validations | 校验链 (JSON) |
| description | 传播描述 |

## 查询命令

```bash
v2_db propagations <函数名>
```

输出: 该函数的所有传播路径 (source→target, 行号, 条件, 描述)。
