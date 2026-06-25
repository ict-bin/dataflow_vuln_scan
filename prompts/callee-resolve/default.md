# 跟入点函数名解析确认

你在分析一个函数的污点传播时，识别出了一些需要跟入的 callee。
其中部分 callee 的函数名在 funcdb 中未精确匹配到定义，脚本通过
最长前缀/后缀分段匹配找到了候选函数。

请判断每个候选是否确实是被调用的函数。

## 判断依据

**confirmed=true（是同一函数）**：
- 反编译器前缀/后缀变体：`j_Foo` → `Foo`，`nullsub_Foo` → `Foo`，`Foo_wrapper` → `Foo`
- C++ 部分限定：`Class::Method` → `NS::Class::Method`（调用时省略命名空间）
- C++ 重载：同名函数有多个定义，根据调用点参数数量/类型选择最匹配的

**confirmed=false（不是同一函数）**：
- 候选函数名只是碰巧有公共子串，实际是完全不同的函数
- 候选在错误的文件中（与调用点所在文件无关且无 include 关系）

## C++ 注意事项

- `j_NS::Class::Method` 通常是 `NS::Class::Method` 的跳转 thunk
- `Class::Method` 可能是 `NS1::Class::Method` 或 `NS2::Class::Method`，需看文件和上下文
- 同名重载函数：根据调用点传入的参数数量和类型判断是哪个重载
- 模板实例化：`Foo<int>` 和 `Foo<char>` 是不同函数，但如果 funcdb 只存了 `Foo` 则可以确认

## 兜底规则

- 如果拿不准，confirmed=true（宁可跟入不漏）
- 如果有多个候选，选择最可能的那个作为 resolved_name
- 如果所有候选都不对，confirmed=false

## 输出格式

```json
{
  "results": [
    {"original": "j_FuncA", "confirmed": true, "resolved_name": "FuncA"},
    {"original": "FuncB_stub", "confirmed": false}
  ]
}
```

- `original`：调用点的原始函数名，与输入列表中的完全一致
- `confirmed`：布尔值，true=候选确实是被调用的函数
- `resolved_name`：确认后选中的候选函数名（confirmed=true 时必填）

不要输出 JSON 以外的内容。
