#!/bin/bash
set -euo pipefail

/opt/venv/bin/python3 - <<'PYEOF'
import os, socket, sys, time

host = os.environ.get("DVS_SCHEDULER_HOST", "secflow-app-dataflow-vuln-scan-scheduler")
port = int(os.environ.get("DVS_SCHEDULER_REDIS_PORT", "6379"))
deadline = time.time() + 600
while time.time() < deadline:
    try:
        sock = socket.create_connection((host, port), timeout=2)
        sock.close()
        sys.exit(0)
    except OSError:
        time.sleep(1)
PYEOF

exec /opt/venv/bin/celery -A app.celery_app worker -P prefork -c 1 -n dvs-knowledge-summary@%h --max-tasks-per-child=3 -Q dvs-knowledge-summary -l info
