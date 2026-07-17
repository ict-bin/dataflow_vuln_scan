# 数据流跟踪剪枝方案设计

## 一、当前跟踪链分析

### 数据统计（任务 dvs_7aa13bab03544516, epoch 6）

| 指标 | 数量 |
|------|------|
| processed_taints (唯一分析) | 103 |
| taint 分析会话 | 131 |
| vuln 挖掘会话 | 103 |
| 传播边 (orchestration edges) | 102 |
| LLM 报告的传播总数 | 1488 |
| 其中逃逸传播 (escape) | 421 |
| 其中外部库调用传播 | 881 (59%) |

### 浪费模式分类

#### 模式 A：外部库安全函数传播（881 条，59%）

LLM 将以下安全工具函数作为传播目标报告，但它们不是安全 sink：

| 目标函数 | 传播数 | 说明 |
|----------|--------|------|
| safe_strncpy | 197 | 带长度限制的安全拷贝，非 sink |
| memcpy | 110 | 内存拷贝，非 sink |
| dns_add_OPT_ECS | 65 | DNS 选项构建，内部函数 |
| tlog | 13 | 日志，非安全相关 |
| dns_add_domain | 13 | DNS 域名添加，内部 |
| snprintf | 7 | 格式化，非 sink |
| dns_packet_init | 7 | 包初始化，内部 |
| dns_get_A | 4 | DNS 记录获取，内部 |
| (空 target) | 463 | LLM 格式错误/未填 target_function |

**影响**：每条传播可能触发后续跟踪 + vuln 挖掘会话，全部产出 0 漏洞。

#### 模式 B：重复逃逸模式（421 条）

同一个逃逸模式被每个调用点重复报告：

| 逃逸模式 | 次数 | 占比 |
|----------|------|------|
| carrier=request → dns_query_queue via _dns_server_do_query | 153 | 36% |
| carrier=request → request via _dns_server_do_query | 62 | 15% |
| carrier=context → dns_response_packet via dns_add_OPT_ECS | 32 | 8% |
| carrier=inpacket → network via _dns_server_tcp_socket_send | 17 | 4% |

**根因**：`request` 结构体被 `list_add_tail` 挂入全局链表是真实逃逸，但每个调用
`_dns_server_do_query` 的函数都报告同样的逃逸。去重后只需记录一次。

#### 模式 C：配置/标志检查函数（0 传播，0 返回污点）

以下函数接收 `taint=request` 但只读取 `request->flags` 或 `request->conf->*`，
不传播污点到任何 sink：

```
_dns_server_force_dualstack      — 检查 dualstack 标志，返回 -1/0
_dns_server_get_local_ttl        — 从配置读 TTL
_dns_server_get_reply_ttl        — 从配置读 TTL
_dns_server_has_bind_flag        — 检查 server_flags & flag
_dns_server_query_end            — 管理引用计数
_dns_server_request_remove_all   — 释放请求，无数据流
_dns_server_check_complete_dualstack — 检查条件返回
_dns_server_set_dualstack_selection — 设置标志位
_dns_server_check_set_passthrough  — 设置 passthrough 标志
```

**影响**：这些函数的 taint 分析产出 0 传播、0 返回污点，但仍跑了完整 LLM 会话。
vuln 挖掘会话也产出 0 漏洞。

#### 模式 D：无效污点导致的空分析

LLM 从 callee 返回值中错误识别了不存在的污点，导致 re-analysis 时找不到对应变量：

```
_dns_server_prefetch_request  taint=dns_msg  → 0 props, 0 rts (无此变量)
_dns_server_prefetch_request  taint=dst      → 0 props, 0 rts (无此参数)
_dns_server_prefetch_request  taint=result   → 0 props, 0 rts (返回 int 状态码)
_dns_server_reply_https       taint=alpn_selected → 0 props, 0 rts (内部标志)
```

**影响**：浪费 LLM 调用做无意义的重新分析。

#### 模式 E：leaf 函数的无效 vuln 挖掘

| vuln 挖掘位置 | 会话数 | 发现漏洞数 |
|--------------|--------|-----------|
| leaf 函数（无 in-tree callee） | 65 (63%) | 2 |
| 非 leaf 函数 | 38 (37%) | (大部分) |

**注**：2 个 finding 来自 sink 函数（`_dns_server_reply_udp` 等网络发送函数），
而非配置/标志函数。配置/标志函数的 vuln 挖掘 100% 产出 0。

---

## 二、剪枝方案设计

### 剪枝 1：外部库安全函数黑名单

**位置**：`orchestrator._build_paths()` 中 `_prop_backed_by_taint` 过滤之后

**逻辑**：定义安全工具函数黑名单，传播的 target_function 在黑名单中时，
不创建 ChainStep（不跟入），但仍记录 propagation 到 DB（保持调用树可见）。

```python
# orchestrator.py 顶部
_SAFE_UTIL_BLACKLIST = frozenset({
    "safe_strncpy", "memcpy", "memset", "memmove", "memcmp",
    "tlog", "tlog_printf", "tlog_info", "tlog_debug", "tlog_error",
    "snprintf", "vsnprintf", "strncpy", "strcpy", "strlen", "strcmp", "strncmp",
    "dns_add_domain", "dns_add_OPT_ECS", "dns_add_OPT",
    "dns_packet_init", "dns_get_A", "dns_get_AAAA", "dns_get_CNAME",
    "dns_cache_lookup", "dns_cache_release", "dns_cache_update",
    "dns_cache_get_ttl", "dns_cache_total_num",
    "dns_cache_get_query_flag", "dns_cache_get_dns_group_name",
    "dns_cache_insert", "dns_cache_replace",
    "hash_string", "jhash", "hash_add", "hash_add_head", "hash_del",
    "atomic_read", "atomic_inc", "atomic_inc_return", "atomic_set",
    "pthread_mutex_lock", "pthread_mutex_unlock",
    "time", "clock_gettime", "gettimeofday",
})
```

**在 `_build_paths` 中过滤**：

```python
# 在 props_sorted 过滤后，构造 ChainStep 时跳过黑名单目标
for p in props_sorted:
    ...
    elif p.is_external_callee or p.target_function in _SAFE_UTIL_BLACKLIST:
        # callee 是外部库或安全工具函数 — 记录传播但不跟入
        continue
```

**预期效果**：消除 881 条传播的后续跟踪（59%），减少 ~40% 的下游分析。

### 剪枝 2：逃逸模式全局去重

**位置**：`orchestrator._process()` step 3（upsert_propagation 之前）

**逻辑**：维护一个进程级 `_seen_escapes: set[(carrier, target_taint, escape_via)]`。
如果逃逸模式已记录，跳过该 propagation（不 upsert，不触发后续跟踪）。

```python
# orchestrator.py DfsOrchestrator.__init__
self._seen_escapes: set[tuple[str, str, str]] = set()

# _process step 3, 遍历 result.propagations 时
for p in result.propagations:
    if p.is_external:
        escape_key = (_norm(p.carrier), _norm(p.target_taint), _norm(p.escape_via))
        if escape_key in self._seen_escapes:
            continue  # 已记录过此逃逸模式，跳过
        self._seen_escapes.add(escape_key)
    self.store.upsert_propagation(p)
```

**预期效果**：421 条逃逸传播去重为 ~67 条唯一模式，减少 85% 重复逃逸传播。

### 剪枝 3：空结果跳过 vuln 挖掘

**位置**：`orchestrator._process()` step 4/6（mine_vulns 调用前）

**逻辑**：如果 taint 分析结果 `result.propagations` 为空且 `result.return_taints` 为空，
说明该 (func, taint) 组合没有数据流向任何 sink，跳过 vuln 挖掘。

```python
# step 4 (self_contained=True) 和 step 6 (self_contained=False)
if self_contained and not result.taint_failed:
    if result.propagations or result.return_taints:
        self._run_llm(self.cbs.mine_vulns, ...)
    else:
        logger.info("[V2-orch] skip mine_vulns: no props, no return_taints for %s taint=%s",
                    func.name, taint_params.signature)
```

**预期效果**：跳过 17 个空分析 + ~20 个配置/标志函数的 vuln 挖掘，减少 ~35% vuln 会话。

### 剪枝 4：配置/标志函数预分类

**位置**：`function_extractor.ensure_file_indexed()` 或 `orchestrator._process()` 入口

**逻辑**：用 tree-sitter 静态分析函数体，检测以下模式：
- 函数体只包含 `if (request->xxx == yyy)` / `request->conf->zzz` 条件判断
- 函数体只包含 `request->flag |= xxx` / `request->flag = xxx` 标志设置
- 没有调用任何网络发送函数（sendto/sendmsg/SSL_write/dns_client_query）
- 没有指针解引用写入（`*ptr = tainted`）

```python
def _classify_config_function(func_body: str) -> bool:
    """检测配置/标志检查函数：只有条件判断和标志设置，无数据流到 sink。"""
    # 有网络发送调用 → 不是配置函数
    for sink in NETWORK_SINK_PATTERNS:
        if sink in func_body:
            return False
    # 只有 if/return/赋值标志 → 是配置函数
    has_data_write = bool(re.search(r'\*\w+\s*=', func_body))  # 指针解引用写入
    has_func_call = bool(re.search(r'\w+\s*\(', func_body))     # 有函数调用
    if not has_data_write and not has_func_call:
        return True
    # 所有函数调用都在安全工具黑名单中 → 是配置函数
    calls = re.findall(r'(\w+)\s*\(', func_body)
    external_calls = [c for c in calls if c not in _SAFE_UTIL_BLACKLIST and not c.startswith('_dns_server')]
    if not external_calls:
        return True
    return False
```

**效果**：配置/标志函数仍运行一次 taint 分析（确认无数据流），但跳过 vuln 挖掘。
~10 个函数 × 1 taint = 10 个 vuln 会话被跳过。

### 剪枝 5：无效返回污点过滤

**位置**：`orchestrator._process()` step 7（return_taints 循环）

**逻辑**：在 step 7 重新分析前，检查 return_taint 的名字是否在目标函数的参数列表中。
如果不在参数列表也不在已知局部变量中，跳过重新分析。

```python
# step 7
for rt in all_callee_return_taints:
    rt_sig = _norm_taint_sig(rt.signature or rt.name)
    # 检查 rt.name 是否在目标函数中存在
    if not _taint_exists_in_function(func, rt.name):
        logger.info("[V2-orch] skip return_taint: %s not found in %s",
                    rt.name, func.name)
        continue
```

**预期效果**：跳过 14 个无效 return_taint 的重新分析（`dns_msg`, `dst`, `result`,
`alpn_selected` 等），减少 ~14 个无用 taint 分析 + 对应 vuln 挖掘。

---

## 三、预期效果汇总

| 剪枝策略 | 减少传播 | 减少分析 | 减少 vuln 会话 | 减少总量 |
|----------|---------|---------|---------------|---------|
| 1. 安全函数黑名单 | 881 | ~40 | ~40 | ~560 |
| 2. 逃逸去重 | 354 | ~30 | ~30 | ~400 |
| 3. 空结果跳过挖掘 | 0 | 0 | ~37 | ~37 |
| 4. 配置函数分类 | 0 | 0 | ~10 | ~10 |
| 5. 无效返回污点过滤 | 0 | ~14 | ~14 | ~28 |
| **合计** | **1235** | **~84** | **~131** | **~1035** |

**预计效果**：
- 分析会话从 234 → ~150（减少 36%）
- vuln 挖掘会话从 103 → ~0 无效挖掘（保留 sink 函数挖掘）
- 总 LLM 调用减少 ~40%
- 任务完成时间减少 ~40%

## 四、实现优先级

1. **剪枝 1（安全函数黑名单）**：最高优先级，效果最大，实现最简单
2. **剪枝 2（逃逸去重）**：高优先级，消除重复逃逸
3. **剪枝 3（空结果跳过挖掘）**：中优先级，简单有效
4. **剪枝 5（无效返回污点过滤）**：中优先级，需参数列表检查
5. **剪枝 4（配置函数分类）**：低优先级，需 tree-sitter 静态分析
