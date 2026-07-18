"""Request/Response Pydantic models for dataflow-vuln-scan API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TaskCreateRequest(BaseModel):
    project_id: str
    task_name: str
    input_path: str
    module_input_path: Optional[str] = None
    source_root_path: Optional[str] = None
    output_path: Optional[str] = None
    task_description: Optional[str] = None
    prompt_template_id: Optional[str] = None
    prompt_content: Optional[str] = None
    source_file: Optional[str] = None
    function_name: Optional[str] = None
    line_hint: Optional[str] = None
    definition_kind: Optional[str] = None
    taint_params: list[str] = []
    taint_details: list[Dict[str, Any]] = []
    function_description: Optional[str] = None
    function_description_source: Optional[str] = None
    entry_reason: Optional[str] = None
    entry_reason_source: Optional[str] = None
    task_origin_type: Optional[str] = None
    parent_project_id: Optional[str] = None
    parent_task_id: Optional[str] = None
    parent_task_type: Optional[str] = None
    parent_stage_name: Optional[str] = None
    parent_stage_item_id: Optional[str] = None
    parent_stage_item_key: Optional[str] = None
    agent_task_key_id: Optional[str] = None
    agent_task_key_name: Optional[str] = None
    agent_task_key_prefix: Optional[str] = None
    agent_task_key_secret: Optional[str] = None
    agent_task_key_source: Optional[str] = None
    model: Optional[str] = None
    # 任务级 debug 特性开关, 见 TaskConfig.feature_flags (clang_mutex / vuln_verifier)
    feature_flags: Dict[str, bool] = {}


class TaskFeatureFlagsRequest(BaseModel):
    """PATCH /tasks/{task_id}/feature-flags 请求体: 合并到 task_config_json.feature_flags。"""
    feature_flags: Dict[str, bool]


class GeneratePromptRequest(BaseModel):
    input_path: str


class TaskSessionIndexNodeResponse(BaseModel):
    node_id: str
    relative_path: str
    session_name: str
    display_name: str
    role: str
    role_label: str
    status: str
    is_active: bool = False
    stage_key: str
    stage_label: str
    stage_order: int = 0
    stage_group: str
    module_name: Optional[str] = None
    attempt: Optional[int] = None
    judge_index: Optional[int] = None
    batch_index: Optional[int] = None
    parent_relative_path: Optional[str] = None
    parallel_group: Optional[str] = None
    family_key: Optional[str] = None
    flow_kind: Optional[str] = None
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    started_ts: Optional[float] = None
    last_event_at: Optional[str] = None
    last_event_ts: Optional[float] = None
    mtime: float = 0
    size: int = 0
    event_count: int = 0
    line_count: int = 0
    warnings: List[str] = []
    session_header: Dict[str, Any] = {}
    cwd: Optional[str] = None
    model: Optional[str] = None
    latest_round_ref: Optional[Dict[str, Any]] = None
    round_refs: List[Dict[str, Any]] = []
    attempts_seen: List[int] = []


class TaskSessionIndexEdgeResponse(BaseModel):
    edge_id: str
    source_node_id: str
    target_node_id: str
    kind: str
    label: str


class TaskSessionIndexGroupResponse(BaseModel):
    group_id: str
    kind: str
    label: str
    stage_key: Optional[str] = None
    module_name: Optional[str] = None
    node_ids: List[str] = []


class TaskSessionIndexResponse(BaseModel):
    version: int = 1
    generated_at: Optional[str] = None
    task_id: str
    task_status: str
    status: Optional[str] = None
    sessions_root: Optional[str] = None
    index_path: Optional[str] = None
    summary: Dict[str, Any] = {}
    nodes: List[TaskSessionIndexNodeResponse] = []
    edges: List[TaskSessionIndexEdgeResponse] = []
    groups: List[TaskSessionIndexGroupResponse] = []
    warnings: List[str] = []


class WorkerActiveJobResponse(BaseModel):
    task_id: str
    task_name: str
    status: str
    parent_task_id: str | None = None
    parent_task_type: str | None = None
    task_origin_type: str | None = None
    input_path: str
    started_at: str | None = None
    updated_at: str | None = None
    dispatch_status: str | None = None
    execution_owner_id: str | None = None
    execution_lease_until: str | None = None
    execution_heartbeat_at: str | None = None
    mapped: bool = True
    mapping_reason: str = "matched_execution_owner"


class WorkerCapacityResponse(BaseModel):
    worker_id: str
    host_name: str
    pod_name: str | None = None
    pod_ip: str | None = None
    http_port: int | None = None
    healthy: bool
    max_concurrent_jobs: int
    running_jobs: int = 0
    available_slots: int = 0
    source: str = "lease_registry"
    last_heartbeat_at: str | None = None
    pod_created_at: str | None = None
    pod_started_at: str | None = None
    pod_metrics_at: str | None = None
    pod_cpu_usage_millicores: int | None = None
    pod_memory_usage_bytes: int | None = None
    pod_cpu_request_millicores: int | None = None
    pod_memory_request_bytes: int | None = None
    pod_cpu_limit_millicores: int | None = None
    pod_memory_limit_bytes: int | None = None
    active_jobs: list[WorkerActiveJobResponse] = Field(default_factory=list)
    error: str | None = None


class WorkerClusterCapacityResponse(BaseModel):
    worker_count: int = 0
    healthy_workers: int = 0
    stale_workers: int = 0
    total_capacity: int = 0
    running_jobs: int = 0
    queued_jobs: int = 0
    available_slots: int = 0
    updated_at: str | None = None
    workers: list[WorkerCapacityResponse] = Field(default_factory=list)


class AgentProcessSnapshotResponse(BaseModel):
    pod_name: str
    pid: int
    pgid: Optional[int] = None
    ppid: Optional[int] = None
    command: str
    cwd: Optional[str] = None
    exe: Optional[str] = None
    rss_bytes: Optional[int] = None
    runtime_kind: Optional[str] = None
    match_source: Optional[str] = None
    match_confidence: Optional[str] = None
    workspace_root: Optional[str] = None
    task_id: Optional[str] = None
    task_name: Optional[str] = None
    task_status: Optional[str] = None
    stage_key: Optional[str] = None
    role_kind: Optional[str] = None
    owner_kind: str
    owner_reason: str
    kill_allowed: bool = False
    kill_block_reason: Optional[str] = None
    termination_state: str


class AgentTaskOwnershipSnapshotResponse(BaseModel):
    task_id: str
    task_name: str
    task_status: str
    stage_key: Optional[str] = None
    pod_name: str
    process_count: int = 0
    agent_roles: list[str] = Field(default_factory=list)
    process_pids: list[int] = Field(default_factory=list)
    ownership_status: str


class AgentPodSnapshotResponse(BaseModel):
    pod_name: str
    worker_id: Optional[str] = None
    healthy: bool = True
    process_count: int = 0
    tracked_process_count: int = 0
    residual_process_count: int = 0
    unknown_process_count: int = 0
    total_pi_process_count: int = 0
    residual_pi_process_count: int = 0
    unknown_pi_process_count: int = 0
    residual_pi_detected: bool = False
    task_count: int = 0
    running_task_count: int = 0
    residual_task_count: int = 0
    last_idle_pi_reaper_at: Optional[float] = None
    last_idle_pi_reaper_killed_count: int = 0
    last_scanned_at: Optional[float] = None
    scan_errors: int = 0
    processes: list[AgentProcessSnapshotResponse] = Field(default_factory=list)
    tasks: list[AgentTaskOwnershipSnapshotResponse] = Field(default_factory=list)


class AgentObservabilitySummaryResponse(BaseModel):
    pod_name: str
    active_processes: int = 0
    residual_processes: int = 0
    unknown_processes: int = 0
    killable_residual_processes: int = 0
    killable_unknown_processes: int = 0
    total_pi_process_count: int = 0
    residual_pi_process_count: int = 0
    unknown_pi_process_count: int = 0
    residual_pi_detected: bool = False
    last_idle_pi_reaper_at: Optional[float] = None
    last_idle_pi_reaper_killed_count: int = 0
    scanned_at: Optional[float] = None
    scan_errors: int = 0
    aggregate_mode: Optional[str] = None
    aggregate_partial: Optional[bool] = None
    aggregate_sources: Optional[int] = None
    aggregate_fanout_errors: Optional[int] = None
    aggregate_duration_seconds: Optional[float] = None
    aggregate_cache_hit: Optional[bool] = None
    aggregate_cache_age_seconds: Optional[float] = None
    aggregate_failed_targets: list[str] = Field(default_factory=list)
    aggregate_failed_target_details: list[dict[str, Any]] = Field(default_factory=list)
    aggregate_all_sources_failed: Optional[bool] = None
    total_pods: Optional[int] = None
    healthy_pods: Optional[int] = None


class AgentProcessKillItemResponse(BaseModel):
    pid: int
    pgid: Optional[int] = None
    status: str
    reason: Optional[str] = None


class AgentProcessKillResponse(BaseModel):
    requested: int
    matched: int
    succeeded: int
    failed: int
    skipped: int
    items: list[AgentProcessKillItemResponse] = Field(default_factory=list)


class AgentRuntimeAggregateSummaryResponse(BaseModel):
    total_pods: int = 0
    healthy_pods: int = 0
    total_processes: int = 0
    tracked_processes: int = 0
    residual_processes: int = 0
    unknown_processes: int = 0
    killable_residual_processes: int = 0
    killable_unknown_processes: int = 0
    aggregate_partial: bool = False
    aggregate_sources: int = 0
    aggregate_fanout_errors: int = 0
    aggregate_failed_targets: list[str] = Field(default_factory=list)
    aggregate_failed_target_details: list[dict[str, Any]] = Field(default_factory=list)
    aggregate_all_sources_failed: bool = False
    scanned_at: Optional[float] = None


class AgentRuntimeAggregateResponse(BaseModel):
    summary: AgentRuntimeAggregateSummaryResponse
    pods: list[AgentPodSnapshotResponse] = Field(default_factory=list)
    processes: list[AgentProcessSnapshotResponse] = Field(default_factory=list)
    tasks: list[AgentTaskOwnershipSnapshotResponse] = Field(default_factory=list)


class TaskTimelineEventResponse(BaseModel):
    id: str
    task_id: str
    project_id: str
    source: str
    level: str
    event_type: str
    status: str | None = None
    worker_id: str | None = None
    execution_owner_id: str | None = None
    execution_epoch: int | None = None
    control_version: int | None = None
    dispatch_status: str | None = None
    function_name: str | None = None
    source_file: str | None = None
    line_hint: str | None = None
    parent_task_id: str | None = None
    parent_stage_item_id: str | None = None
    message: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    recorder_instance_id: str | None = None
    recorder_hostname: str | None = None
    recorder_pod_name: str | None = None
    recorder_node_name: str | None = None
    recorder_pod_ip: str | None = None
    recorder_role: str | None = None
    origin_instance_id: str | None = None
    origin_hostname: str | None = None
    origin_pod_name: str | None = None
    origin_node_name: str | None = None
    origin_pod_ip: str | None = None
    origin_role: str | None = None
    created_at: str | None = None
    type: str | None = None
    data: Dict[str, Any] = Field(default_factory=dict)


class TaskTimelineResponse(BaseModel):
    task_id: str
    events: list[TaskTimelineEventResponse] = Field(default_factory=list)


class TaskPropagationItemResponse(BaseModel):
    prop_id: str
    source_func_id: str | None = None
    source_function: str | None = None
    source_file: str | None = None
    source_taint_name: str = ""
    source_taint_signature: str = ""
    target_taint_name: str = ""
    target_taint_signature: str = ""
    target_func_id: str | None = None
    target_function: str | None = None
    target_file: str | None = None
    call_line: int | None = None
    condition: str | None = None
    description: str | None = None
    validations: list[dict[str, Any]] = Field(default_factory=list)
    actual_args: list[str] = Field(default_factory=list)
    is_external: bool = False
    is_indirect_call: bool = False
    is_external_callee: bool = False
    dispatch_kind: str | None = None
    escape_kind: str | None = None
    carrier: str | None = None
    escape_via: str | None = None
    callsite_validated: bool = False
    branch_group_id: str | None = None
    branch_arm_id: str | None = None
    mutex_siblings: list[str] = Field(default_factory=list)
    propagation_method: str = ""
    orchestration_followed: bool = False
    orchestration_status: str | None = None
    unfollowed_reason: str | None = None
    unfollowed_reason_source: str | None = None
    followup_status: str | None = None
    followup_reason_raw: str | None = None


class TaskPropagationsResponse(BaseModel):
    task_id: str
    run_root: str
    available: bool = False
    items: list[TaskPropagationItemResponse] = Field(default_factory=list)


class ActionResponse(BaseModel):
    status: str = "ok"
    task_id: str
    message: str
    deleted_event_count: int = 0


class TaskListStatsResponse(BaseModel):
    total: int = 0
    pending: int = 0
    running: int = 0
    passed: int = 0
    failed: int = 0
    error: int = 0
    cancelled: int = 0
