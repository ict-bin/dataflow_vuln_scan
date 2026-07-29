#!/bin/bash
# Worker 启动: 自等 redis (broker) 就绪再启 celery。
#
# 根因: k8s 部署无时序保证, scheduler pod 的 redis 容器可能晚于 worker pod 就绪。
# celery 启动期 broker 不可用时, 即使 broker_connection_retry_on_startup=True 最终连上、
# main process 标记 ready, consumer/prefork pool 仍可能半残 — 不响应 inspect ping、
# 不从队列消费 (已观测 5/8 worker 卡此态)。pod 自己 gate broker 依赖, 根除该故障条件。
set -euo pipefail

/opt/venv/bin/python3 - <<'PYEOF'
import os, socket, time, sys
host = os.environ.get("DVS_SCHEDULER_HOST", "secflow-app-dataflow-vuln-scan-scheduler")
port = int(os.environ.get("DVS_SCHEDULER_REDIS_PORT", "6379"))
deadline = time.time() + 600  # 最多等 10min (redis 调度器拉起期间)
logged = False
while time.time() < deadline:
    try:
        s = socket.create_connection((host, port), timeout=2)
        s.close()
        print(f"[worker] redis broker {host}:{port} reachable, starting celery", flush=True)
        sys.exit(0)
    except OSError:
        if not logged:
            print(f"[worker] waiting for redis broker {host}:{port} (k8s 无启动时序, pod 自 gate)...", flush=True)
            logged = True
        time.sleep(1)
print(f"[worker] redis {host}:{port} unreachable after 10min; starting celery anyway (retry-on-startup 兜底)", flush=True)
PYEOF

# 挂载 v2-database skill 到 pi (LLM 需要看到 SKILL.md 才能正确调用 v2_db)
mkdir -p /root/.pi/agent/skills
ln -sf /opt/dataflow_vuln_scan/skills/v2/v2-database /root/.pi/agent/skills/v2-database

exec /opt/venv/bin/celery -A app.celery_app worker -P prefork -c 1 -n dvs-worker@%h --max-tasks-per-child=10 -Q dvs -l info
