# dataflow_vuln_scan（数据流漏洞挖掘服务）— 当前架构总览

> 本文基于代码现状（submodule HEAD `b222b67`，分支 `v2.0-34-gb222b67`）撰写，描述**实际运行**的架构，与 README 中的早期 Worker+Judge 模型已有重大差异。

---

## 0. 一句话定位

基于 [pi](https://github.com/mariozechner/pi) 多智能体框架的 **C/C++ 数据流污点分析系统**：从已知入口函数出发，递归追踪外部输入在调用链中的传播路径，把污点节点/边/清洗/校验写入 **task-local SQLite 图数据库**，并 fork 漏洞挖掘上下文判定是否形成漏洞，最终输出漏洞 finding 报告。

服务代号 `secflow-app-dataflow-vuln-scan`，API 前缀 `/api/app/dataflow-vuln-scan`，菜单挂在「应用工具 → 数据流漏洞挖掘 → 数据流漏洞追踪」。

---

## 1. 仓库与部署信息

| 项 | 值 |
|----|----|
| 代码位置 | `13-secflow-service/image_build/secflow-app-dataflow-vuln-scan`（**git submodule**，独立仓库） |
| 父仓库分支 | `v2.1`，远程 `https://github.com/runshine/sothoth.git` |
| CI workflow | `.github/workflows/build-secflow-app-dataflow-vuln-scan-image.yaml`（多架构 push 到 `ghcr.io/runshine/secflow-app-dataflow-vuln-scan` 与 Docker Hub） |
| 镜像 | `ghcr.io/runshine/secflow-app-dataflow-vuln-scan:latest`（基础镜像 `dfa-base:layer5`：Node+pi、Python3、ripgrep、`extract_func`） |
| K8s 命名空间 | `secflow-ns` |
| 部署目录 | `101-Chimera-deploy/02-secflow-app/`（114 系列 6 个 yaml） |
| 前端 | `13-secflow-service/image_build/secflow-frontend`（独立 submodule，React+Vite+TS，文件在仓库根而非 `src/`） |

### 1.1 K8s 拓扑（已实测在线运行）

```
secflow-ns
├── Deployment: secflow-app-dataflow-vuln-scan        (role=api)   replicas=2  HPA 2~3
│   └── DVS_ROLE=api, ENABLE_PUBLIC_API=true, DISPATCHER=false, EXECUTOR=false, REGISTRY=true
├── Deployment: secflow-app-dataflow-vuln-scan-worker (role=worker) replicas=8  HPA 8~8(固定)
│   └── DVS_ROLE=worker, ENABLE_DISPATCHER=true, ENABLE_EXECUTOR=true, MAX_LOCAL_RUNNING_TASKS=1
├── Service: secflow-app-dataflow-vuln-scan  ClusterIP 80→8080  (selector role=api)
└── 共享卷: secflow-platform-fileserver-data-nfs-pvc → /data  (任务产物/源码/NFS 共享)
```

- **API Pod（2 副本）**：只跑 FastAPI + 注册到 menu + 健康探针，**不执行**分析任务。
- **Worker Pod（8 副本）**：每个 Pod `MAX_LOCAL_RUNNING_TASKS=1`，即单 Pod 同时只跑 1 个任务（一个任务内部还有 BFS 工作池并发）。8 Pod × 1 = 集群理论并发 8 个任务。HPA min=max=8，当前为固定值。
- 两个 Deployment 共用同一镜像，靠 `DVS_ROLE` 环境变量切换启用的后台线程。
- 健康探针走独立 `18080` 端口的 `ThreadedProbeServer`（`/healthz` `/readyz` `/startupz`），与业务 `8080` 解耦；`SECFLOW_EXTERNAL_PROBE_PROCESS=1` 时探针为独立子进程（`scripts/start-with-probe.sh`）。
- 当前实测 Pod：2 个 api + 6 个 worker（HPA 8，实际 6 个 Running，1 个还在启动）。

### 1.2 前端关键文件

```
secflow-frontend/
├── clients/appDataflowVulnScan.ts        # 后端 API 客户端（含 trace 树类型）
├── clients/dataflowVulnRunsFileserver.ts # 任务产物文件服务
├── clients/dataflowVulnScanner.ts
├── pages/execution/
│   ├── DataflowVulnScanTaskPage.tsx       # 任务列表 + 创建 + 集群容量/Worker 槽位
│   ├── DataflowVulnScanTaskDetailPage.tsx # 任务详情：trace 树 + session 回放 + 产物
│   ├── DataflowVulnScanConfigPage.tsx     # 服务配置（Worker/Judge 角色、模型、提示词目录）
│   ├── DataflowVulnScannerPage.tsx
│   ├── DataflowFileserverRunDashboardPage.tsx
│   └── binarySecurityMetricsDataflowVuln.tsx
└── app/navigation.tsx / app/viewRegistry.tsx  # 路由注册
```

前端 `BASE = /api/app/dataflow-vuln-scan`。

---

## 2. 运行时角色与启动流程（`runtime_context.py` + `runtime_bootstrap.py`）

`DVS_ROLE` 决定一个 Pod 启用哪些子系统（`all/api/worker`，默认 `all`）：

| 能力开关 | api | worker | 含义 |
|----------|-----|--------|------|
| `PUBLIC_API_ENABLED` | ✅ | ❌ | 暴露管理 API（/tasks 等）与旧版 /analyse |
| `REGISTRY_ENABLED` | ✅ | ❌ | 向 menu 服务注册自身 |
| `DISPATCHER_ENABLED` | ❌ | ✅ | 轮询 DB 认领任务（dispatch loop） |
| `EXECUTOR_ENABLED` | ❌ | ✅ | 本地执行任务（拉起 Orchestrator） |
| `WORKER_SLOT_REGISTRY_ENABLED` | ❌ | ✅ | worker 槽位心跳上报 + 孤儿任务回收 |

`RuntimeBootstrap._bootstrap_loop`（守护线程，重试到全部就绪）按序拉起：

1. **DB init** → `init_db`（MySQL `secflow.app_dvs_*` 表），失败重试。
2. **management router**（仅 api）→ 把 `app/api` 管理路由挂到 FastAPI。
3. **registry**（仅 api）→ `registry_service.register()/start()`，向 menu 注册并心跳。
4. **dispatcher**（仅 worker）→ 起 `dvs_dispatcher` 线程：循环 `task_service.dispatch_until_full()` 认领任务直到本地槽位满。
5. **worker_slot**（仅 worker）→ 起 `dvs_worker_slot_registry` 线程：周期 `upsert_heartbeat`（pod/max_concurrent/status）+ `reconcile_orphaned_running_tasks`（回收租约过期的 running 任务）。
6. **running_task_reconcile**（worker dispatcher 子线程）→ 周期校验本地 `_running_tasks` 上下文与 DB 是否一致，修挂的任务。

探针 `/readyz` 综合判断：bootstrap 就绪 ∧ worker 角色需心跳新鲜 ∧ supervisor 线程活 ∧ 控制面 lag ≤5s ∧ 未在关停。

---

## 3. 整体架构图

```
                         ┌─────────────────────────────────────────────┐
   SecFlow 前端 (React)  │  /api/app/dataflow-vuln-scan/{tasks,config} │
                         └──────────────────────┬──────────────────────┘
                                                │ HTTP (Ingress→Service:80→8080)
                         ┌──────────────────────▼──────────────────────┐
                         │        API Pod  (role=api, ×2, HPA 2~3)      │
                         │  FastAPI (app/server.py + app/api/tasks.py)  │
                         │  ─ 任务 CRUD / 时间线 / 评估 / agent 观测     │
                         │  ─ registry → menu 服务注册                   │
                         │  ─ metrics (prometheus + summary)            │
                         │  ─ 把任务写入 MySQL(app_dvs_tasks)            │
                         └──────────────────────┬──────────────────────┘
                                                │ MySQL (secflow.app_dvs_*)
                                                │ + NFS /data 共享
                         ┌──────────────────────▼──────────────────────┐
                         │     Worker Pod (role=worker, ×8, 固定 8)     │
                         │  dispatch loop: 认领 pending/续租 running     │
                         │  ┌─────────────────────────────────────────┐ │
                         │  │  TaskService.execute_task (1 per pod)   │ │
                         │  │   └─ Orchestrator.execute_recursive()    │ │
                         │  │       (BFS 队列 + 工作池)                 │ │
                         │  │         └─ pi 子进程 (Worker agent)       │ │
                         │  │         └─ SQLite 图数据库 vuln-scan.sqlite│ │
                         │  └─────────────────────────────────────────┘ │
                         │  worker_slot 心跳 / 孤儿任务回收 / pi reaper  │
                         └─────────────────────────────────────────────┘
                                                │
                                       NFS /data/output/<task_id>/
                                                │
                                       前端读取产物 / 下载报告
```

外部依赖：MySQL（任务表/事件表/worker_slot 表）、NFS（源码只读 + 产物读写）、menu/auth/configcenter 服务、内网 vllm（LLM 推理）。

---

## 4. 任务生命周期与执行流图

### 4.1 管理层（API Pod → MySQL → Worker Pod）

```
[前端创建任务]
   │ POST /tasks  (project_id, task_name, prompt, cwd, source_file, function_name, taint_*)
   ▼
TaskService.create_task  →  写 app_dvs_tasks(status=pending, control_version=0, task_config_json)
   │                      →  写 input manifest（源码路径校验/规范化）
   ▼
MySQL: status=pending, dispatch_status=NULL
   │
   │  Worker Pod dispatch loop 每 3s 轮询：
   ▼
claim_one_runnable_task  (lease 过期或空的 pending/running 任务，乐观更新 epoch+1, owner=WORKER_ID, lease=now+TTL)
   │  对 running 任务回收 → 标 _force_clean_restart（**无 resume，一律 clean restart 清空任务目录从头跑**）
   ▼
TaskService.execute_task 线程:
   1. still_owner 校验 → begin_execution_if_owner(status=running)
   2. 起 lease 续租心跳线程（renew_lease，TTL=300s/心跳 60s）
   3. 物化任务级 pi runtime（models.json + api key + skills + 提示词目录）
   4. Orchestrator(config).execute_recursive(task_id, _root_out_dir=run/epochs/<epoch>)
   5. 全程 SwarmEvent → 写 app_dvs_task_events（时间线）+ flush stages_json
   6. 终态 commit_terminal_state_if_owner(status=passed/failed/error, result_json, stages_json)
   7. release_lease；cleanup pi 进程；归档产物到 output/
```

任务状态机：`pending → running → passed/failed/error/cancelled`。`restart` = 清空目录 + control_version+1 + 重置为 pending。`resume` 已移除，等同 restart。

### 4.2 引擎层（Orchestrator，单任务内部）

`execute_recursive` = **BFS 队列 + 工作池**，根任务（depth=0）独占调度：

```
ROOT (depth=0)
 │
 ├─[预阶段A 可选] 入口快速筛查 (entry_point_screener)
 │    白名单子串命中 → 放行(0 token)
 │    否则 1 轮独立 pi agent 判 is_entry
 │      ├ true  → 继续
 │      └ false → 早退 PASSED(not_entry_point)，写报告，结束
 │
 ├─[预阶段B 常开] 污点源自动识别 (taint_source_identifier)
 │    仅当 taint_params/taint_details 为空或哨兵 'all'
 │    嵌入完整函数体 → 1 轮独立 pi agent → 回填 cfg.taint_params/taint_details
 │    失败安全：识别为空 → 退回 'all'
 │
 ├─ 初始化：graph_db = run/vuln-scan.sqlite, vuln_output_root=run/vulnerabilities/
 ├─ queue.put(根函数)
 │
 ▼  ─── BFS 工作池 (n_workers = callee_concurrency，默认4，1=串行) ───
 │  worker(i): while item=queue.get():
 │    process_item(item):
 │      1. 虚函数 stub 重定向（_resolve_virtual_override_if_stub，多候选→fork 全部分支）
 │      2. DataflowVulnWorkflow（单函数 W+脚本校验，见 4.3）
 │      3. 解析 followups（从图数据库 followups 表 / Worker 的 tainted.list）
 │      4. nonlocal tracker（污点写入全局/字段容器 → 独立搜读取者作为新跟入点，按符号集去重防回环）
 │      5. followup_resolver：精确/模糊/LLM 确认 解析 callee 定义
 │      6. param_analyzer：分流 P0(顺序,非const指针) / P2(隔离,值类型)
 │      7. branch_pruner（可选）：剪枝无效分支
 │      8. 对每个有效 callee：
 │           - grep 预检 _function_has_definition（跳过 stdlib/extern 声明）
 │           - 去重 analyzed.add(key)，key=source_file:function
 │           - queue.put((callee, depth+1, tainted_ctx, followup_id, context_id))
 │      9. 漏洞挖掘 fork（vuln_mining_thread）：fork 上下文判定本函数内是否成漏洞 → finding
 │
 ▼  queue.join() 全部完成
 │
 ├─ 合并所有 all_results：rounds/tokens/duration
 ├─ root_result.final_output = _build_vulnerability_brief_report（漏洞简报列表，完整图谱以 sqlite 为准）
 └─ _do_final_archive：run/ → output/（复制 sqlite、报告、压缩 sessions）
```

### 4.3 单函数分析 `execute()`（DataflowVulnWorkflow 驱动）

```
对函数 F（depth, max_depth, taint_ctx 注入）:
 │
 ├─ 准备 worker 工作目录 workspace-worker-i/（符号链接 target 文件 + tmp 隔离 + HOME/TMPDIR env）
 ├─ 构建 worker_prompt（task/context/round/feedback/function/source_file/taint_details/depth 注入）
 │
 └─ Rounds 循环 (1..max_rounds, -1=∞；受 min_rounds/pass_threshold):
      ├─ Worker agent (pi 子进程, run_agents_parallel, concurrency=worker_count)
      │    系统提示词 prompts/workers/default.md（含 write-dataflow skill 指令）
      │    工具: read/bash/edit/write/find + extract_func
      │    产物: dataflow-<func>.md（污点传播分析）, tainted.list（callee 污点参数）
      │    后置 RPC 第二轮：强制写 tainted.list
      │
      ├─ 后置脚本校验（非 Judge！）：
      │    F1 未写 dataflow / 内容<100 → issue
      │    F2 不含目标函数名 → issue
      │    vuln_graph_validator 校验 taint-graph/dataflow/tainted.list 结构合同
      │    合同失败 → feedback 注入下一轮 Worker
      │
      ├─ DataflowVulnWorkflow.run()：
      │    解析 dataflow-*.md → 写入 graph_db(taint_nodes/taint_edges/followups/...)
      │    计算 callsite taint signature（callsite_analysis）
      │    fork 漏洞挖掘上下文 → vulnerability_findings
      │
      ├─ pass 判定：脚本校验通过 ∧ 达 min_rounds → round 通过
      │    失败 → feedback_md → 下一轮
      └─ 通过 → 解析 callee/followups 返回给 BFS
```

**关键现状**：`worker_count = min(1, len(workers.agents))` 即恒为 1；`judge_count = 0`。
所以**当前是「单 Worker + 脚本校验」模型**，README 里的多 Worker/多 Judge 并行已被简化。前端配置页也注明「本微服务不使用 Judge；Worker 输出由后端脚本校验结构合同」。

---

## 5. 并行控制总览

| 层次 | 机制 | 并发度 | 代码位置 |
|------|------|--------|----------|
| **集群任务并发** | worker Pod × `MAX_LOCAL_RUNNING_TASKS` | 8 Pod × 1 = 8 | `runtime_context.py`, deployment env |
| **任务认领** | dispatch loop + DB 乐观锁（owner/epoch/lease） | 每 Pod 1 认领线程 | `execution_coordinator.claim_one_runnable_task`, `task_service.dispatch_until_full` |
| **租约保活** | renew_lease 心跳线程 + TTL 300s | 每运行任务 1 线程 | `task_service._start_task_lease_heartbeat` |
| **孤儿回收** | worker_slot 心跳 + reclaim_orphaned_running_tasks | 周期跑 | `runtime_bootstrap._start_worker_slot_registry` |
| **BFS 工作池（任务内 callee 并发）** | `threading.Thread` × `callee_concurrency` 消费同一 `Queue` | 默认 4，1=串行，-1=4 | `orchestrator.execute_recursive` worker 池 |
| **单函数 Worker 并发** | `run_agents_parallel` | `worker_count=1`（已收敛为 1） | `orchestrator.execute`, `runner.py` |
| **多 Judge 并发** | — | 0（已移除） | — |
| **漏洞挖掘 fork** | `vuln_mining_thread`（join 后再继续） | 1 | `orchestrator` process_item |
| **虚函数多候选** | fork 全部 override 候选入队 | 候选数 | `_resolve_virtual_override_if_stub` |
| **P0 顺序 / P2 隔离** | scheduler.Slot（DFS 累积 TaintState） + 全局 BFS 队列 | P0 串行、P2 并行 | `scheduler.py`, `param_analyzer` |

> 注意：README 顶部画的 `asyncio.gather` 并行在当前代码里已改为 **threading + Queue** 的 BFS 工作池（与 CLAUDE.md「后台服务禁用 asyncio」一致）；asyncio 仅留在 FastAPI 路由层与 runner 内 pi 进程流式读取。

---

## 6. 各阶段产物

任务根目录 `/data/output/<task_id>/`（NFS 共享，跨 Pod 可见），布局：

```
<task_id>/
├── input/                        # 输入清单（源码路径校验、上游 EA 元数据）
│   └── input-manifest.json
├── run/                          # 执行工作区
│   ├── epochs/<epoch>/           # 每次 restart/clean-restart 一个 epoch 子目录
│   │   ├── flag                  # 0=未完成/失败, 1=PASSED
│   │   ├── sessions/             # 所有 pi agent 会话回放
│   │   │   ├── worker-0.jsonl
│   │   │   ├── d00-entry-screen.jsonl
│   │   │   ├── d00-taint-source-id.jsonl
│   │   │   └── <session_label>-tracker-nonlocal.jsonl
│   │   ├── workspace-worker-0/   # Worker 工作目录（target 符号链接 + 产物）
│   │   │   ├── dataflow-<func>.md
│   │   │   └── tainted.list
│   │   ├── round_001/{workers,judges}/
│   │   ├── subtasks/depth_01/<tid>-<func>/  # 递归子函数分析（非根 execute 的 run_dir）
│   │   ├── vuln-scan.sqlite      # ★ 图数据库（核心产物）
│   │   └── vulnerabilities/<finding_id>/    # 单个漏洞 finding
│   │       ├── taint-path-report.md
│   │       ├── context.jsonl
│   │       └── vulnerability-report.md
│   └── (共享 run/ 下放 graph_db 与 vulnerabilities)
├── output/                       # 最终归档（复制自 run）
│   ├── flag
│   ├── <src>_<Func>.md           # 漏洞简报报告（final_output）
│   ├── vuln-scan.sqlite
│   ├── vulnerabilities/
│   └── <src>_<Func>_log.zip      # sessions 压缩包
└── (DB) app_dvs_tasks.result_json / stages_json
```

### 6.1 SQLite 图数据库表（`vuln_store.py`，核心数据源）

| 表 | 内容 |
|----|------|
| `analysis_runs` | 一次函数级分析运行：task/根文件/根函数/源码根/状态/配置快照 |
| `taint_nodes` | 污点源与中间载体：kind(param/return_value/call_argument/local/field/global/unknown)、symbol、line、parent_node_id、depth、context_session |
| `taint_edges` | 单函数内传播边：from→to、operation(assignment/call_arg/return/field/container/condition/sink/terminate/validation/sanitizer)、evidence(带行号)、sanitizer、sanitizer_effect、validation、termination_reason |
| `followups` | 跟入点：callee 函数/文件/行/污点参数、dispatch_kind、状态(pending/queued/running/completed/skipped/cycle/depth_limit/forked/error)、tracker 状态 |
| `vulnerability_findings` | 漏洞记录，指向 output/vulnerabilities/<id>/ |
| `context_forks` | fork 上下文：purpose(vulnerability_mining/followup_analysis) |
| `analysis_contexts` | 分析上下文状态 |
| `taint_constraints` | 污点约束 |
| `container_taints` | 容器型污点（用于 nonlocal tracker） |
| `meta` | 元信息 |

### 6.2 DB 任务表（`app/db/models.py`，`app_dvs_*`）

- `app_dvs_tasks`：task_id、project_id、status、task_config_json、result_json、stages_json、execution_owner_id/epoch/lease_until/heartbeat_at（租约）、control_version、dispatch_status、latest_abnormal_reason_json、started_at/finished_at、is_deleted。
- `app_dvs_task_events`：任务时间线事件（SwarmEvent 落库，前端 timeline 回放）。
- worker_slot 表：worker_id/pod_name/pod_ip/max_concurrent/last_heartbeat/status。

### 6.3 阶段事件流（SwarmEvent，可观测）

```
task_start → trace_start →
  entry_screen_start → entry_screen_whitelisted|pass|reject
  taint_autodetect_start → taint_autodetect_done|empty
  (per function BFS)
    trace_start(func,depth) → worker_start → worker_stream → worker_done
    → tracker_start(nonlocal) → tracker_done
    → trace_redirect(virtual override) | trace_skip(no followups)
    → vuln_scan_start → vuln_finding_found
    → trace_pass | trace_fail
  round_start/round_end
→ trace_done → task_done(PASSED/FAILED/ERROR)
异常：task_not_owner_pre_execute / dispatcher_claim_batch / task_running_reconcile_batch / control_plane_event_loop_stall_detected
```

---

## 7. 关键 API（`app/api/tasks.py`，前缀 `/api/app/dataflow-vuln-scan`）

| 方法 | 路径 | 用途 |
|------|------|------|
| POST | `/tasks` | 创建任务（project_id/task_name/prompt/cwd/source_file/function_name/taint_*） |
| GET | `/tasks` | 任务列表（project_id 过滤、分页） |
| GET | `/tasks/{id}` | 任务详情（result_json + stages） |
| GET | `/tasks/{id}/logs` | 实时阶段事件（timeline） |
| GET | `/tasks/{id}/evaluation` | 任务评估（rounds/worker/session 摘要） |
| GET | `/tasks/{id}/sessions` | session 索引（回放目录） |
| GET | `/tasks/{id}/sessions/content` | session 文件内容 |
| POST | `/tasks/{id}/cancel` | 取消（control_version+1） |
| POST | `/tasks/{id}/restart` | 重新运行（清空目录 + control_version+1） |
| POST | `/tasks/{id}/resume` | 断点续跑（已等同 restart） |
| DELETE | `/tasks/{id}` | 软删除 |
| GET | `/tasks/stats` | 任务统计 |
| GET | `/workers/cluster-capacity` | 集群容量（聚合 worker slot） |
| GET | `/workers/slot-cluster` / `/projects/{pid}/slot-cluster` | 全局/项目槽位视图 |
| GET | `/agent-observability/{snapshot,summary,aggregate/summary,processes,aggregate/processes,sessions/content,tasks}` | agent 观测（fanout 到各 worker pod） |
| GET | `/prompts` / POST `/prompts` / ... | 提示词模板 CRUD |
| POST | `/generate-prompt` | 根据路径生成 prompt |
| GET | `/metrics` `/metrics/aggregate` `/metrics/summary` `/metrics/rest-api-summary` `/metrics/ai-summary` | prometheus + 可观测摘要 |
| GET | `/health` `/ready` | 业务观测（非 kube probe） |

旧版兼容路由（`PUBLIC_API_ENABLED` 才开放）：`POST /analyse`、`GET /task/{id}`、`GET /task/{id}/stream`(SSE)、`POST /task/{id}/abort`、`GET /tasks`、`GET /health`。

agent-observability 类接口会 `_resolve_worker_targets` 后 **fanout 到各 worker Pod 的 8080** 聚合快照（API Pod 代理查询 worker）。

---

## 8. 提示词与 Skill 体系

```
prompts/
├── workers/default.md          # 主 Worker：taint-graph + dataflow + tainted.list
├── entry-screen/default.md     # 入口筛查（thinking off，只看函数头）
├── taint-source-id/default.md  # 污点源自动识别（嵌入完整函数体）
├── taint-graph/default.md
├── vuln-miners/default.md      # 漏洞挖掘 fork
├── followups/default.md        # 跟入点解析
├── callee-resolve/default.md   # callee 模糊解析 LLM 确认
├── branch-pruning/default.md   # 分支剪枝
├── judges/default.md           # （保留，当前 judge_count=0 不启用）
└── merge/default.md            # （旧合并 agent，已由 sqlite 取代）

skills/  (安装到 ~/.pi/agent/skills/)
├── write-dataflow/
├── write-taint-flow/
├── write-taint-graph/
└── mine-dataflow-vulnerability/
```

工具：`tools/extract_func.py`（容器内 `/usr/local/bin/extract_func`，精确提取 C/C++ 函数体，避免读大文件）、`tools/gen_dataflow.py`、`tools/gen_tainted_list.py`。

---

## 9. 容错与恢复策略

| 场景 | 行为 |
|------|------|
| LLM 限流/网络超时 | 指数退避，最多 `agent_max_retries`（默认 -1=无限？实际 config 给 50） |
| pi 进程启动失败 | 重试 `pi_max_retries`（-1=无限） |
| 模型未找到/401 | 致命，立即终止不重试 |
| Worker 超时 | `agent_timeout_retry_enabled`，`agent_timeout_max_retries` |
| 任务租约过期（worker 失联） | worker_slot 回收 → 标 `_force_clean_restart` → 回 pending 重新认领（**无 checkpoint resume**） |
| 虚函数 stub 多候选 | fork 全部 override 入队并行分析 |
| 环路（同状态键重复） | `analyzed` set + nonlocal 符号集去重，标记 cycle/back-edge，不再无限展开 |
| 达 max_trace_depth | 记 depth_limit followup，callee 表仍填但不再递归 |
| callee 无定义/stdlib/extern | grep 预检跳过 |
| 入口筛查/污点识别失败 | 失败安全：一律按「是入口/全函数」继续，不误杀 |

`.task_version`（V2.0）控制任务目录布局兼容性；大版本变更会清空旧任务目录。

---

## 10. 本机 K8s 观测速查

```bash
# Pod
kubectl -n secflow-ns get pods -l name=secflow-app-dataflow-vuln-scan -o wide
# 进 worker pod 看任务产物
kubectl -n secflow-ns exec -it deploy/secflow-app-dataflow-vuln-scan-worker -- ls /data/output
kubectl -n secflow-ns exec -it deploy/secflow-app-dataflow-vuln-scan-worker -- sqlite3 /data/output/<task_id>/run/vuln-scan.sqlite ".tables"
# 健康
kubectl -n secflow-ns exec -it deploy/secflow-app-dataflow-vuln-scan-worker -- curl -s localhost:18080/readyz | jq .
# 集群容量（API 聚合）
curl -s http://secflow-app-dataflow-vuln-scan.secflow-ns/api/app/dataflow-vuln-scan/workers/cluster-capacity
```

---

## 11. 与 README 的差异提醒（开发注意）

1. **Worker/Judge 并行已收敛**：`worker_count≡1`、`judge_count≡0`，单函数靠「脚本校验 + 多轮 feedback」替代 Judge 评分。改并行需改 `models.py` 的 `worker_count`/`judge_count` 属性与 `execute()`。
2. **BFS 并发用 threading + Queue**，不是 README 画的 asyncio.gather（遵守 CLAUDE.md「后台禁 asyncio」）。
3. **核心产物是 `vuln-scan.sqlite` 图数据库**，最终报告只是漏洞简报；前端 trace 树/详情都读 sqlite。
4. **resume 已移除**，任何恢复（rollout/失联/租约过期）= clean restart（清空任务目录从头跑）。
5. **API/Worker 同镜像双 Deployment**，靠 `DVS_ROLE` 切角色；改后台线程逻辑注意两份 deployment env。
6. 任务级 pi runtime（models.json/api key/skills/提示词）由 `task_service._materialize_task_pi_runtime` 在执行前物化到任务目录，按角色隔离。
