#!/opt/venv/bin/python
"""自主模式服务工具: checkpoint '<JSON>'

LLM 结束一轮探索时调 → 写 checkpoint.json (pending_branches + continue + stop_reason)。
服务 AutonomousRunner 读 checkpoint.json 决定是否续探。

用法: checkpoint '{"continue": true, "stop_reason": "context_full",
                    "pending_branches": [{"at_func":"...","target":"...","taint":"...","reason":"..."}]}'

环境变量:
  DVS_RUN_DIR  - 任务 run 目录 (checkpoint.json 所在)
"""
import json
import logging
import os
import sys
import time

logger = logging.getLogger("dvs.autonomous.checkpoint")

RUN_DIR = os.environ.get("DVS_RUN_DIR") or ""
CHECKPOINT_PATH = os.path.join(RUN_DIR, "checkpoint.json") if RUN_DIR else ""


def main():
    logging.basicConfig(level=os.environ.get("DVS_LOG_LEVEL", "INFO"), stream=sys.stderr,
                        format="%(levelname)s %(name)s: %(message)s")
    if len(sys.argv) < 2:
        print("用法: checkpoint '<JSON: {continue, stop_reason, pending_branches}>'", file=sys.stderr)
        sys.exit(2)
    try:
        data = json.loads(sys.argv[1])
        if not isinstance(data, dict):
            raise ValueError("checkpoint 必须是 JSON 对象")
    except Exception as e:
        print(f"[checkpoint] JSON 解析失败: {e}", file=sys.stderr)
        sys.exit(2)
    if not CHECKPOINT_PATH:
        print("[checkpoint] DVS_RUN_DIR 未设置", file=sys.stderr)
        sys.exit(1)
    data["ts"] = time.time()
    # 续探轮次递增 (服务读最新)
    try:
        prev = 0
        if os.path.exists(CHECKPOINT_PATH):
            prev = json.load(open(CHECKPOINT_PATH, encoding="utf-8")).get("round", 0)
        data["round"] = prev + 1
    except Exception as e:
        logger.warning("read prev checkpoint round failed, default to 1: %s", e)
        data["round"] = 1
    with open(CHECKPOINT_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(json.dumps({"status": "ok", "round": data["round"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
