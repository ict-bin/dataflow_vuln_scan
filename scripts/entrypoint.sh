#!/bin/bash
# 容器入口脚本
# 确保 pi 配置目录存在，然后执行传入的 CMD

set -e

# Increase file descriptor limit to prevent "Too many open files" during
# BFS call-tree exploration with many concurrent subprocess invocations.
# Default Docker/K8s soft limit is 1024, which is easily exhausted.
if [ "$(ulimit -n)" -lt 65535 ]; then
    ulimit -n 65535 2>/dev/null || echo "[entrypoint] WARNING: could not raise ulimit -n to 65535"
    echo "[entrypoint] ulimit -n: $(ulimit -n)"
fi

PI_DIR="${PI_CODING_AGENT_DIR:-/root/.pi/agent}"
mkdir -p "$PI_DIR"

if [ -f /data/config/models.json ]; then
    ln -sf /data/config/models.json "$PI_DIR/models.json"
    echo "[entrypoint] linked /data/config/models.json -> $PI_DIR/models.json"
fi

if [ -d /data/config/prompts ]; then
    echo "[entrypoint] custom prompts found at /data/config/prompts/"
fi

exec "$@"
