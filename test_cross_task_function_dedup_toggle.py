"""Regression coverage for the global cross-task function dedup switch."""

from __future__ import annotations

import tempfile
import unittest

from app.config import build_task_config
from app.dagflow.dag_store import DagflowStore
from app.dataflow_v2.models import ProcessedTaint
from app.dataflow_v2.store import DataflowStore
from app.models import ServiceConfig


class _FakeMysqlStore:
    def __init__(self) -> None:
        self.find_calls = 0
        self.reserve_calls = 0
        self.delete_calls = 0

    def v2_find_processed_taint(self, *_args):
        self.find_calls += 1
        return object()

    def v2_try_reserve_processed_taint(self, *_args):
        self.reserve_calls += 1
        return False

    def v2_delete_processed_taint(self, *_args):
        self.delete_calls += 1

    def dag_find_processed(self, *_args):
        self.find_calls += 1
        return True

    def dag_try_reserve(self, *_args):
        self.reserve_calls += 1
        return False

    def dag_delete_processed(self, *_args):
        self.delete_calls += 1


class TestCrossTaskFunctionDedupToggle(unittest.TestCase):
    def test_default_is_enabled_and_is_copied_to_task_config(self):
        service = ServiceConfig()
        task = build_task_config(service, "分析 main.c 中 parse_message 的数据流", cwd="/tmp/source")

        self.assertTrue(service.cross_task_function_dedup_enabled)
        self.assertTrue(task.cross_task_function_dedup_enabled)

    def test_disabled_service_config_is_copied_to_task_config(self):
        service = ServiceConfig(cross_task_function_dedup_enabled=False)
        task = build_task_config(service, "分析 main.c 中 parse_message 的数据流", cwd="/tmp/source")

        self.assertFalse(task.cross_task_function_dedup_enabled)

    def test_v2_store_skips_claim_operations_when_disabled(self):
        mysql = _FakeMysqlStore()
        processed = ProcessedTaint(taint_signature="payload")
        with tempfile.TemporaryDirectory() as tmp:
            store = DataflowStore(
                tmp,
                mysql_store=mysql,
                cross_task_function_dedup_enabled=False,
            )
            self.assertIsNone(store.find_processed_taint("func-1", "payload"))
            self.assertTrue(store.try_reserve_processed_taint("func-1", processed))
            store.delete_processed_taint("func-1", "payload")

        self.assertEqual(0, mysql.find_calls)
        self.assertEqual(0, mysql.reserve_calls)
        self.assertEqual(0, mysql.delete_calls)

    def test_dagflow_store_skips_claim_operations_when_disabled(self):
        mysql = _FakeMysqlStore()
        with tempfile.TemporaryDirectory() as tmp:
            store = DagflowStore(
                tmp,
                mysql_store=mysql,
                cross_task_function_dedup_enabled=False,
            )
            self.assertFalse(store.find_processed_taint("func-1", "payload"))
            self.assertTrue(store.try_reserve("func-1", "payload"))
            store.delete_processed_taint("func-1", "payload")

        self.assertEqual(0, mysql.find_calls)
        self.assertEqual(0, mysql.reserve_calls)
        self.assertEqual(0, mysql.delete_calls)


if __name__ == "__main__":
    unittest.main()
