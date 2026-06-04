import tempfile
import unittest
from pathlib import Path

from app.vuln_graph_service import load_vuln_scan_graph, summarize_graph
from app.vuln_graph_validator import validate_taint_graph
from app.vuln_store import TaintEdgeRecord, TaintSourceRecord, VulnFindingRecord, VulnScanStore


class VulnGraphStoreTests(unittest.TestCase):
    def test_store_records_tree_and_findings(self):
        root = Path(tempfile.mkdtemp())
        store = VulnScanStore(root / "vuln-scan.sqlite")
        store.start_run("run1", "task1", "a.c", "foo", "/src", {"max_depth": 3})
        store.upsert_taint_node(TaintSourceRecord(
            node_id="n1", source_file="a.c", function_name="foo", taint_kind="param", symbol="buf"
        ))
        store.add_taint_edges([TaintEdgeRecord(
            edge_id="e1", run_id="run1", from_node_id="n1", to_node_id="n2",
            source_file="a.c", function_name="foo", from_symbol="buf", to_symbol="len",
            line="L10", operation="assignment", evidence="L10: len = buf->len"
        )])
        store.add_finding(VulnFindingRecord(
            finding_id="v1", run_id="run1", node_id="n1", vuln_type="overflow", title="overflow"
        ))
        graph = load_vuln_scan_graph(root)
        self.assertEqual({"runs": 1, "nodes": 1, "edges": 1, "followups": 0, "findings": 1}, summarize_graph(graph))
        self.assertEqual("buf", graph["taint_nodes"][0]["symbol"])

    def test_validator_requires_edge_evidence(self):
        warnings = validate_taint_graph({
            "function": "foo",
            "source_file": "a.c",
            "edges": [{"from": "a", "to": "b", "operation": "terminate"}],
            "followups": [],
        })
        self.assertTrue(any("missing line" in item for item in warnings))
        self.assertTrue(any("termination_reason" in item for item in warnings))


if __name__ == "__main__":
    unittest.main()
