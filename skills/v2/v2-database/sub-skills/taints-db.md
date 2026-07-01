# 污点库 (taints.db) 详细用法

## 数据库结构

| 字段 | 说明 |
|------|------|
| taint_id | 污点唯一 ID |
| func_id | 所属函数 ID |
| name | 污点变量名 |
| signature | 变量签名/类型 |
| file / function | 源文件 / 函数名 |
| description | 污点描述 (LLM 分析后填入) |

## 查询命令

```bash
v2_db taints <函数名>
```

输出: 该函数的所有污点变量列表 (名称 + 签名 + 描述)。
