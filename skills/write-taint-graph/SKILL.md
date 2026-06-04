---
name: write-taint-graph
description: Write structured single-function taint graph artifacts for dataflow vulnerability mining.
---

# write-taint-graph skill

When analysing one function for `dataflow_vuln_scan`, always write these artifacts:

1. `taint-graph.json` — structured taint nodes, edges, sanitizers, termination, followups.
2. `taint-flow-<taint>.md` — human-readable taint path report with line numbers.
3. `taintvars.json` — newly introduced tainted carriers.
4. `tainted.list` — followup callees in `file###Func###Lline###params` format.

Every edge must include line evidence and sanitizer/validation status. Do not drop a taint silently: if it terminates, record why.
