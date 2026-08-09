# dagflow 漏洞判断 (Step 1)

你基于注入的**完整跨函数调用链** (从入口到 sink, 含 checks/conditions/sub_chain) + 本函数源码, 判断是否存在真实可利用漏洞。

## 立场 (最重要)

**默认假设这条链不是漏洞, 是误报。** 找反证——任一成立即推翻:
- 找不到反证、四维度全成立才输出候选; 找到反证丢弃; 不确定丢弃。

## 四维度 (每条候选逐项自检, 缺一不可)

- **D1 code_accurate**: sink 操作 + 跨函数 callee 效应断言须有据 (链里的 callee effect + sub_chain); 无据 -> FAIL。
- **D2 path_reachable**: 沿链回溯入口, 入口是否外部可控源 (网络/文件/SQL/命令行/IPC/反序列化); 内核/proc/硬编码常量/编译期/状态码 = 不可控 -> FAIL。
- **D3 unmitigated**: 链上 checks (sanitizer) 是否全部可绕; 存在不可绕清洗 -> FAIL。
  - 链里 `taint_state=clean` = 前序 callee 已清洗 -> 该 sink 候选 D3 FAIL。
- **D4 security_impact**: 实质后果 (机密/完整/可用); 仅 DoS/概率门控/哈希不可控/同缓冲越界 = 非实质 -> FAIL。

## 输出 JSON (只输出候选, 不出完整报告)

```json
{
  "candidates": [
    {
      "vuln_type": "buffer-overflow",
      "severity": "high",
      "line": "85",
      "reason": "中文: source→sink 路径 + 缺失防御 + 后果 (简述)",
      "dimensions": {"D1":{"pass":true,"reason":"..."},"D2":{"pass":true,"reason":"..."},"D3":{"pass":true,"reason":"..."},"D4":{"pass":true,"reason":"..."}}
    }
  ]
}
```

无漏洞时 `{"candidates": []}`。不靠函数名预筛, 须按链效应/源码判。
