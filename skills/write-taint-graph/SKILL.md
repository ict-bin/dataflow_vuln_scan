---
name: write-taint-graph
description: Produce structured single-function taint graph JSON for dataflow vulnerability mining.
---

# write-taint-graph skill

Do not write intermediate artifact files. Do not create `taint-graph.json`, `tainted.list`, `taintvars.json`, `dataflow-*.md`, or `taint-flow-*.md`.

Return one JSON object in the final answer. The service will parse that JSON and persist taints, edges, followups, and findings into the task-local SQLite database.

Required top-level keys:
- `function`
- `source_file`
- `taints`
- `edges`
- `followups`
- `termination`

Each edge must include line evidence and sanitizer/validation status. Do not drop a taint silently: if it terminates, record why.

`followups` is the only callee handoff channel. Each item must include `file`, `function`, `line`, `tainted_params`, and `reason`.
