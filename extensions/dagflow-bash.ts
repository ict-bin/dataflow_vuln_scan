/**
 * dagflow-bash.ts — bash 工具输出限制: grep/find 输出截断, 防 session 膨胀。
 *
 * 根因: LLM 用 grep -rn 搜源码树, 返回数百行 → input token 膨胀 → 会话时间爆炸。
 * 但完全禁止 grep/cat 会导致 LLM 无法快速验证, 反复尝试更慢。
 *
 * 策略: 不禁止工具, 而是限制输出行数:
 * - grep/find 命令: 自动追加 | head -50 (最多 50 行结果)
 * - cat 命令: 提示用 read 工具 (read 有 offset/limit, 更可控)
 * - v2_db.py: 放行不限制
 * - 其他命令: 放行
 */
const MAX_GREP_LINES = 50;

export default function (pi: any) {
  pi.on("tool_call", async (event: any, _ctx: any) => {
    if (event.toolName !== "bash") return;
    const input = event.input;
    if (!input || typeof input.command !== "string") return;

    const cmd = input.command;

    // 放行: v2_db.py 命令不限制
    if (cmd.includes("v2_db.py")) {
      return;
    }

    // grep: 如果没有 | head 或 | tail, 追加 | head -N
    if (/\bgrep\b/.test(cmd) && !/\|\s*(head|tail)\b/.test(cmd)) {
      input.command = cmd + " | head -" + MAX_GREP_LINES;
      return;
    }

    // find: 如果没有 | head 或 | tail, 追加 | head -N
    if (/\bfind\b/.test(cmd) && !/\|\s*(head|tail)\b/.test(cmd)) {
      input.command = cmd + " | head -" + MAX_GREP_LINES;
      return;
    }

    // cat: 提示用 read 工具 (read 有 offset/limit, 更可控)
    // 但如果 cat 已带管道 (如 cat file | grep), 放行
    if (/^\s*cat\s+/.test(cmd) && !/\|/.test(cmd)) {
      input.command =
        'echo "[dagflow-bash] cat 整文件输出可能过大。'
        + ' 请用 read 工具 (带 offset/limit) 或 python3 /opt/dataflow_vuln_scan/tools/v2_db.py lookup <函数名>"';
      return;
    }

    // 其他命令: 放行
    return;
  });
}
