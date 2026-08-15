/** Restrict knowledge-summary Agent shell calls to a fixed read-only helper. */
export default function (pi: any) {
  pi.on("tool_call", async (event: any, _ctx: any) => {
    if (event.toolName !== "bash" || !event.input || typeof event.input.command !== "string") return;
    const encoded = Buffer.from(event.input.command, "utf8").toString("base64");
    event.input.command = `/opt/venv/bin/python3 /opt/dataflow_vuln_scan/bin/knowledge_summary_readonly.py --command ${encoded}`;
  });
}
