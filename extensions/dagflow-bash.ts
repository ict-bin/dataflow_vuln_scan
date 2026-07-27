/**
 * dagflow-bash.ts — bash 工具白名单: 只允许 v2_db.py 命令, 阻止 grep/find/cat/head/tail/sed。
 *
 * 根因: prompt 写了 "禁止 grep/find, 走 v2_db", 但 LLM 无视 prompt,
 * 仍然用 bash 跑 grep -rn 返回大量源码行 → input token 膨胀 → 会话时间爆炸。
 *
 * 修复: 在 tool_call 事件层拦截, 只放行含 v2_db.py 的 bash 命令,
 * 其余 grep/find/cat/head/tail/sed/awk 等全部拒绝。
 * LLM 只能用 v2_db 查函数/符号 + read 工具读特定文件。
 */
const V2DB = "/opt/dataflow_vuln_scan/tools/v2_db.py";

const BLOCKED = /\b(grep|find|cat|head|tail|sed|awk|xxd|strings|objdump|nm)\b/;

export default function (pi: any) {
  pi.on("tool_call", async (event: any, _ctx: any) => {
    if (event.toolName !== "bash") return;
    const input = event.input;
    if (!input || typeof input.command !== "string") return;

    const cmd = input.command;

    // 放行: 含 v2_db.py 的命令
    if (cmd.includes(V2DB) || cmd.includes("v2_db.py")) {
      return;
    }

    // 阻止: grep/find/cat 等搜源码命令
    if (BLOCKED.test(cmd)) {
      // 替换为提示, 不执行原命令
      input.command =
        'echo "[dagflow-bash] 禁止用 grep/find/cat 等命令搜源码。'
        + ' 查函数源码: python3 /opt/dataflow_vuln_scan/tools/v2_db.py lookup <函数名>"';
      return;
    }

    // 放行: 其他无害命令 (echo, ls, pwd, wc, python3 非 grep)
    return;
  });
}
