/**
 * restricted-bash.ts — 自主模式 bash 工具拦截: 确保 find/grep/cat 走 bin/restricted wrapper。
 *
 * 根因: pi 的 bash 工具 spawn `bash -c cmd` 时不继承 Popen env 的 PATH,
 * 导致 env 里 bin/restricted 在前也无用, find/grep/cat 解析到 /usr/bin (无限制, 可搜全 NFS)。
 *
 * 修复: tool_call 事件 mutable event.input.command, 给每条 bash 命令前缀
 * `export PATH=<wrapper_dir>:$PATH`, 让 shell 自己 source 后 find/grep/cat 解析到 wrapper
 * (wrapper 把 / 等外部路径替换成 $DVS_SOURCE_ROOT, 或拒绝)。
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const WRAPPER_DIR = "/opt/dataflow_vuln_scan/bin/restricted";

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event, _ctx) => {
    if (event.toolName !== "bash") return;
    const input = event.input as { command?: string } | undefined;
    if (!input || typeof input.command !== "string") return;
    // 前缀 PATH export: 让本次 bash 命令的 find/grep/cat 解析到 restricted wrapper。
    // (wrapper 自身已 export 了也不冲突, 重复前置无害; 对无 find/grep/cat 的命令也无害)
    input.command = `export PATH=${WRAPPER_DIR}:$PATH\n${input.command}`;
  });
}
