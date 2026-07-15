"""
dataflow_vuln_scan — 数据模型
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


MAX_ROUNDS_EXCEEDED_REVIEW_STRATEGIES = {
    "treat_as_passed",
    "treat_as_failed",
}


def normalize_max_rounds_exceeded_review_strategy(value: str | None) -> str:
    candidate = str(value or "").strip().lower()
    if candidate in MAX_ROUNDS_EXCEEDED_REVIEW_STRATEGIES:
        return candidate
    return "treat_as_passed"


def normalize_pass_threshold(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "majority"
    if isinstance(value, int):
        if value <= 0:
            return "majority"
        if value == 1:
            return "majority"
        return "all"
    candidate = str(value).strip().lower()
    if not candidate:
        return None
    if candidate.isdigit():
        return normalize_pass_threshold(int(candidate))
    if candidate in {"all", "majority"}:
        return candidate
    return "majority"


# ─── Agent 实例配置 ───────────────────────────────────────────────────────────

class AgentInstanceConfig(BaseModel):
    model: str = Field(..., description="该实例使用的 LLM 模型")
    tools: Optional[list[str]] = Field(default=None)
    system_prompt: Optional[str] = Field(default=None)
    thinking_level: Optional[str] = Field(default=None)


class RoleConfig(BaseModel):
    default_model: str = Field(default="")
    default_tools: list[str] = Field(default_factory=lambda: ["read", "bash", "edit", "write"])
    system_prompt_dir: str = Field(default="./prompts/workers")
    default_thinking_level: str = Field(default="off")
    agents: list[AgentInstanceConfig] = Field(default_factory=list)


# ─── 服务配置（由管理员一次性配置，长期不变）─────────────────────────────────

# 入口快速筛查默认白名单关键字（小写）：函数名命中任一子串即直接判为入口。
DEFAULT_ENTRY_WHITELIST: list[str] = [
    "recv", "read", "proc", "process", "handle", "parse", "decode",
    "dispatch", "on_", "callback", "ioctl", "input", "msg", "packet",
    "request", "cmd",
]


class ServiceConfig(BaseModel):
    """config.json — 服务提供者配置，不含任务信息"""
    max_rounds: int = Field(default=3, ge=-1, description="每个函数最大 Worker+Judge 迭ge轮数，-1=无限")
    max_rounds_exceeded_review_strategy: str = Field(
        default="treat_as_passed",
        description="达到最大轮次且评审仍未通过时的处理策略：treat_as_passed/treat_as_failed",
    )
    min_rounds: int = Field(default=2, ge=1, le=10, description="最少执行轮数（第1轮后强制自我反思）")
    pass_threshold: Optional[str | int] = Field(default=None, description="裁判通过策略：'all'=全部通过, 'majority'=半数以上(ceil(J/2))，也兼容旧整数阈值配置")
    agent_max_retries: int = Field(default=-1, description="API 错误时最大重试次数")
    agent_retry_delay: float = Field(default=30.0, description="首次重试等待秒数，指数退避")
    agent_run_timeout_seconds: int = Field(default=900, description="单次智能体输入最大空闲时长（秒），仅在完全没有输出/事件时判定超时，-1=不限制")
    agent_timeout_retry_enabled: bool = Field(default=True, description="空闲超时后是否自动重新输入并继续")
    agent_timeout_max_retries: int = Field(default=20, description="空闲超时后最大自动重试次数，-1=无限")
    pi_max_retries: int = Field(default=3, ge=-1, description="pi 进程拉起失败时最大重试次数，-1 为无限重试")
    pi_retry_delay: float = Field(default=10.0, description="pi 进程重试首次等待秒数，指数退避")
    max_trace_depth: int = Field(default=3, ge=1, le=1000, description="函数调用递归追踪最大深度")
    deep_trace_enabled: bool = Field(default=False, description="深度探索模式：不按 max_trace_depth 截断，依赖污点收敛去重")
    callee_concurrency: int = Field(default=4, ge=-1, description="callee 并行分析数：-1=自动/不限, 1=串行, N=最多 N 个并发 BFS 工作池")

    # 入口快速筛查（Entry Screening）：分析前先判断根函数是否为模块入口
    entry_screen_enabled: bool = Field(default=False, description="是否启用入口快速筛查：开启后分析前先判定根函数是否为模块入口，非入口直接以 PASSED 结束并注明理由")
    entry_screen_whitelist: list[str] = Field(default_factory=lambda: list(DEFAULT_ENTRY_WHITELIST), description="入口白名单关键字（小写子串），函数名命中任一即直接判为入口、跳过 agent 判断")
    entry_screen_thinking_level: str = Field(default="off", description="入口筛查 agent 思考等级，默认 off 以省 token")
    branch_pruning_enabled: bool = Field(default=False, description="分支剪枝开关（智能模式）：开启后在污点分析完成后 fork 会话，由 LLM 判断每个 followup 是否值得跟入。关闭=全面模式，所有 followup 全部追踪")

    workers: RoleConfig = Field(default_factory=RoleConfig)
    judges: RoleConfig = Field(default_factory=RoleConfig)

    output_dir: str = Field(default="/data/output")
    archive_dir: str = Field(default="/data/output")
    result_dir: str = Field(default="/data/output")


# ─── 运行时任务（由 ServiceConfig + 用户输入合成）─────────────────────────────

class TaskConfig(BaseModel):
    """运行时完整配置 = 服务配置 + 用户输入"""
    # 用户输入部分
    task: str = Field(..., description="用户的一句话 prompt")
    source_file: str = Field(default="", description="从 prompt 解析出的文件名")
    function_name: str = Field(default="", description="从 prompt 解析出的函数名")
    line_hint: str = Field(default="", description="函数起始行号提示，如 'L228'，用于区分同名重载")
    taint_params: list[str] = Field(default_factory=list, description="显式指定的污点参数列表")
    function_description: str = Field(default="", description="上游入口分析给出的函数职责说明")
    function_description_source: str = Field(default="", description="函数职责说明来源：agent/default")
    entry_reason: str = Field(default="", description="上游入口分析给出的入口判定原因")
    entry_reason_source: str = Field(default="", description="入口判定原因来源：agent/default")
    taint_details: list[dict[str, str]] = Field(default_factory=list, description="上游入口分析给出的逐 taint 说明")
    project_id: str = Field(default="", description="SecFlow 项目 ID，用于漏洞疑点上报")
    task_name: str = Field(default="", description="SecFlow 任务名称，用于漏洞疑点上报元数据")
    parent_task_id: str = Field(default="", description="编排器父任务 ID")
    parent_task_name: str = Field(default="", description="编排器父任务名称，上报漏洞时优先使用此名称")
    parent_task_type: str = Field(default="", description="父任务类型: source=EA, 其他=编排器")
    task_origin_type: str = Field(default="", description="任务来源: binary_security=编排器下发, manual=手动")
    cwd: str = Field(default="/data/target", description="待分析文件所在目录")
    task_pi_dir: str = Field(default="", description="任务级 PI runtime 目录")
    task_pi_dirs: dict[str, str] = Field(default_factory=dict, description="按角色划分的任务级 PI runtime 目录")

    # 服务配置部分（从 ServiceConfig 合并）
    max_rounds: int = Field(default=3)
    max_rounds_exceeded_review_strategy: str = Field(default="treat_as_passed")
    min_rounds: int = Field(default=2)
    pass_threshold: Optional[int] = Field(default=None)
    agent_max_retries: int = Field(default=-1)
    agent_retry_delay: float = Field(default=30.0)
    agent_run_timeout_seconds: int = Field(default=900)
    agent_timeout_retry_enabled: bool = Field(default=True)
    agent_timeout_max_retries: int = Field(default=20)
    pi_max_retries: int = Field(default=3)
    pi_retry_delay: float = Field(default=10.0)
    max_trace_depth: int = Field(default=3)
    deep_trace_enabled: bool = Field(default=False)
    callee_concurrency: int = Field(default=4)
    entry_screen_enabled: bool = Field(default=False)
    entry_screen_whitelist: list[str] = Field(default_factory=lambda: list(DEFAULT_ENTRY_WHITELIST))
    entry_screen_thinking_level: str = Field(default="off")
    branch_pruning_enabled: bool = Field(default=False)
    # 任务级 debug 特性开关 (单任务独立启停, 默认全关 = 主线行为)。
    # 已注册键:
    #   clang_mutex    - clang 互斥分支分析 + 幽灵调用点丢弃 (污点跟踪正确性)
    #   vuln_verifier  - 服务端 finding 结构化核验门 (finding 正确性)
    #   dataflow_v2    - 启用 v2 数据流漏洞挖掘 (四库+路径敏感DFS, 替代 v1)
    #   autonomous_mode - 自主模式: LLM 长程 agent 自主探索 (替代完整模式 DFS); 微服务只记路径+上报漏洞+索引+续探
    feature_flags: dict[str, bool] = Field(default_factory=dict)
    workers: RoleConfig = Field(default_factory=RoleConfig)
    judges: RoleConfig = Field(default_factory=RoleConfig)
    output_dir: str = Field(default="/data/output")
    archive_dir: str = Field(default="/data/output")
    result_dir: str = Field(default="/data/output")
    # context 用于内部递归时注入脏数据上下文，不需用户配置
    context: str = Field(default="", exclude=True)

    @property
    def worker_count(self) -> int:
        return min(1, len(self.workers.agents))

    @property
    def judge_count(self) -> int:
        return 0

    def role_pi_dir(self, role: str) -> str:
        role_key = str(role or "").strip().lower()
        role_dirs = self.task_pi_dirs if isinstance(self.task_pi_dirs, dict) else {}
        candidate = str(role_dirs.get(role_key) or "").strip()
        if candidate:
            return candidate
        return str(self.task_pi_dir or "").strip()


# ─── Token 统计 ───────────────────────────────────────────────────────────────

class TokenUsage(BaseModel):
    input: int = 0
    output: int = 0
    cache_read: int = 0
    cache_write: int = 0
    cost: float = 0.0

    def __iadd__(self, other: TokenUsage) -> TokenUsage:
        self.input += other.input
        self.output += other.output
        self.cache_read += other.cache_read
        self.cache_write += other.cache_write
        self.cost += other.cost
        return self


# ─── 执行结果 ─────────────────────────────────────────────────────────────────

class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    COMPLETED_LIMITED = "completed_limited"
    INVALID_INPUT = "invalid_input"
    FAILED = "failed"
    ERROR = "error"


class WorkerResult(BaseModel):
    worker_id: str
    model: str = ""
    output: str = ""
    dataflow_file: str = ""  # Worker 写入的 dataflow-*.md 路径
    session_file: str = ""
    token_usage: TokenUsage = Field(default_factory=TokenUsage)
    error: Optional[str] = None
    df_issues: list[str] = Field(default_factory=list)  # 结构校验问题列表


class CalleeRef(BaseModel):
    """子函数引用（从 Worker 输出中解析）"""
    function_name: str
    file: str = ""
    line: str = ""
    tainted_params: str = ""
    description: str = ""
    followup_id: str = ""
    dispatch_kind: str = "direct_call"
    tainted_nonlocal: list[dict] = Field(default_factory=list)
    # ── clang 语法解析标注（互斥分支/调用点校验）──
    callsite_validated: bool = False        # clang 确认 caller 体内存在对该 callee 的 CallExpr
    call_line: int = 0                       # clang 命中的真实调用行(0=未校验)
    call_expr: str = ""                      # 调用表达式原文
    branch_path: list[dict] = Field(default_factory=list)   # 包围该调用的 if/switch 祖先链
    branch_group_id: str = ""               # 最内层互斥组 id(兄弟 arm 共享)
    branch_arm_id: str = ""                 # 组内 arm 标识(then/else/case...)
    mutex_siblings: list[str] = Field(default_factory=list)  # 同组不同 arm 的 callee 名
    skip_reason: str = ""                   # phantom_callsite / unresolved / ...


class TraceNode(BaseModel):
    """调用树节点（用于确定性合并）"""
    function_name: str
    depth: int = 0
    dataflow_content: str = ""  # 该函数的 dataflow 文档内容
    status: str = ""  # passed/failed/skipped/depth_limit
    children: list["TraceNode"] = Field(default_factory=list)


class WorkerEvaluation(BaseModel):
    worker_id: str
    passed: bool = False
    score: int = 0
    feedback: str = ""
    refinement: str = ""


class JudgeSummary(BaseModel):
    best_worker_id: str = ""
    reasoning: str = ""
    overall_passed: bool = False


class JudgeRoundResult(BaseModel):
    judge_id: str
    model: str = ""
    session_file: str = ""
    evaluations: list[WorkerEvaluation] = Field(default_factory=list)
    summary: Optional[JudgeSummary] = None
    token_usage: TokenUsage = Field(default_factory=TokenUsage)


class RoundResult(BaseModel):
    round: int
    function_name: str = ""
    source_path: str = ""
    stage: str = "analyse"
    stage_round: int = 0
    started_at: str = ""
    ended_at: str = ""
    duration_ms: float = 0.0
    status: str = ""
    worker_results: list[WorkerResult] = Field(default_factory=list)
    judge_results: list[JudgeRoundResult] = Field(default_factory=list)
    pass_count: int = 0
    total_judges: int = 0
    passed: bool = False
    best_worker_id: str = ""
    feedback_to_workers: str = ""
    module_completed: bool = False
    completion_reason: str = ""


class TaskResult(BaseModel):
    task_id: str
    status: TaskStatus = TaskStatus.RUNNING
    task: str
    analysis_status: str = ""
    completion_reason: str = ""
    config_snapshot: Optional[dict] = None
    upstream_entry_metadata: dict = Field(default_factory=dict)
    taint_hint_summary: list[dict] = Field(default_factory=list)
    rounds: list[RoundResult] = Field(default_factory=list)
    final_output: str = ""
    vuln_summary: dict = Field(default_factory=dict)
    total_duration_ms: float = 0
    total_tokens: TokenUsage = Field(default_factory=TokenUsage)
    error: Optional[str] = None


class SwarmEvent(BaseModel):
    type: str
    task_id: str
    data: dict = Field(default_factory=dict)


def make_id() -> str:
    return f"task-{int(time.time())}-{uuid.uuid4().hex[:8]}"
