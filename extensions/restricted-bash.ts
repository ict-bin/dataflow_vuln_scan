/**
 * restricted-bash.ts — bash 工具拦截: 前缀 PATH 让 find/grep/cat 走 bin/restricted wrapper。
 *
 * 根因: pi 的 bash 工具 spawn bash -c 时不继承 Popen env 的 PATH, 导致 env 里 bin/restricted
 * 在前也无用, find/grep/cat 解析到 /usr/bin (无限制, find / 搜全 NFS)。
 *
 * 修复: tool_call 事件 mutable event.input.command, 给每条 bash 命令前缀
 * `export PATH=<wrapper_dir>:$PATH`, 让 shell source 后 find/grep/cat 解析到 wrapper。
 *
 * 注意: 不用 `import type { ExtensionAPI }` — jiti 可能不擦除 type import,
 * 运行时解析 @earendil-works/pi-coding-agent 失败导致 pi 启动崩。用 any 避免外部依赖。
 */
const WRAPPER_DIR = "/opt/dataflow_vuln_scan/bin/restricted";

export default function (pi: any) {
  pi.on("tool_call", async (event: any, _ctx: any) => {
    if (event.toolName !== "bash") return;
    const input = event.input;
    if (!input || typeof input.command !== "string") return;
    // 前缀 PATH export: 让本次 bash 命令的 find/grep/cat 解析到 restricted wrapper。
    input.command = "export PATH=" + WRAPPER_DIR + ":$PATH\n" + input.command;
  });
}
