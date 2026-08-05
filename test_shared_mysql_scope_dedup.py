import json
import unittest

from app.db.shared_mysql import (
    NO_PARENT_TASK_SCOPE_ID,
    SharedMysqlStore,
    normalize_parent_task_scope_id,
)


class _Result:
    def __init__(self, rowcount=0, row=None):
        self.rowcount = rowcount
        self._row = row

    def fetchone(self):
        return self._row


class _Row:
    def __init__(self, values):
        self._mapping = values


class _Connection:
    def __init__(self, engine):
        self.engine = engine

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, statement, params=None):
        sql = str(statement)
        params = params or {}
        if "FROM processed_taint_scope_claims" in sql and sql.lstrip().upper().startswith("SELECT"):
            key = (params["scope"], params["fid"], params["ts"])
            record = self.engine.claims.get(key)
            return _Result(row=_Row(record) if record else None)
        if "INSERT IGNORE INTO processed_taint_scope_claims" in sql:
            key = (params["scope"], params["fid"], params["ts"])
            if key in self.engine.claims:
                return _Result(rowcount=0)
            self.engine.claims[key] = {
                "taint_signature": params["ts"],
                "taint_params": params["tp"],
                "sessions_path": params["sp"],
                "owner_task_id": params["tid"],
            }
            return _Result(rowcount=1)
        if "INSERT INTO processed_taints" in sql:
            self.engine.audit.add((params["fid"], params["ts"], params["tid"]))
            return _Result(rowcount=1)
        if "DELETE FROM processed_taints" in sql:
            self.engine.audit.discard((params["fid"], params["ts"], params["tid"]))
            return _Result()
        if "DELETE FROM processed_taint_scope_claims" in sql and "WHERE owner_task_id=:tid" in sql:
            self.engine.claims = {
                key: value for key, value in self.engine.claims.items()
                if value["owner_task_id"] != params["tid"]
            }
            return _Result()
        if "DELETE FROM processed_taint_scope_claims" in sql:
            self.engine.claims = {
                key: value for key, value in self.engine.claims.items()
                if not (
                    value["owner_task_id"] == params["tid"]
                    and key[0] == params.get("scope", key[0])
                    and key[1] == params["fid"]
                    and key[2] == params["ts"]
                )
            }
            return _Result()
        return _Result()


class _Engine:
    def __init__(self):
        self.claims = {}
        self.audit = set()

    def connect(self):
        return _Connection(self)

    def begin(self):
        return _Connection(self)


def _store(task_id: str, parent_task_id: str, engine: _Engine) -> SharedMysqlStore:
    store = SharedMysqlStore.__new__(SharedMysqlStore)
    store.task_id = task_id
    store.parent_task_scope_id = normalize_parent_task_scope_id(parent_task_id)
    store.mode = "complete"
    store.source_dir_id = "source"
    store._engine = engine
    return store


class TestSharedMysqlScopeDedup(unittest.TestCase):
    def test_empty_parent_uses_one_stable_scope(self):
        self.assertEqual(NO_PARENT_TASK_SCOPE_ID, normalize_parent_task_scope_id(""))
        self.assertEqual(NO_PARENT_TASK_SCOPE_ID, normalize_parent_task_scope_id(None))
        self.assertEqual("parent-1", normalize_parent_task_scope_id(" parent-1 "))

    def test_same_parent_reuses_but_different_parent_does_not(self):
        engine = _Engine()
        first = _store("task-1", "parent-1", engine)
        second = _store("task-2", "parent-1", engine)
        other = _store("task-3", "parent-2", engine)

        self.assertTrue(first.v2_try_reserve_processed_taint("func-1", "msg[0]", '["msg"]', "s1"))
        self.assertIsNotNone(second.v2_find_processed_taint("func-1", "msg[0]"))
        self.assertFalse(second.v2_try_reserve_processed_taint("func-1", "msg[0]"))
        self.assertIsNone(other.v2_find_processed_taint("func-1", "msg[0]"))
        self.assertTrue(other.v2_try_reserve_processed_taint("func-1", "msg[0]", '["msg"]', "s3"))

    def test_empty_parent_tasks_share_fallback_scope(self):
        engine = _Engine()
        first = _store("task-1", "", engine)
        second = _store("task-2", "  ", engine)
        self.assertTrue(first.v2_try_reserve_processed_taint("func-1", "msg[0]"))
        self.assertFalse(second.v2_try_reserve_processed_taint("func-1", "msg[0]"))

    def test_failed_owner_releases_only_its_scope_claim(self):
        engine = _Engine()
        first = _store("task-1", "parent-1", engine)
        other = _store("task-2", "parent-2", engine)
        self.assertTrue(first.v2_try_reserve_processed_taint("func-1", "msg[0]"))
        self.assertTrue(other.v2_try_reserve_processed_taint("func-1", "msg[0]"))

        first.v2_delete_processed_taint("func-1", "msg[0]")
        self.assertIsNone(first.v2_find_processed_taint("func-1", "msg[0]"))
        self.assertIsNotNone(other.v2_find_processed_taint("func-1", "msg[0]"))

    def test_claim_keeps_per_task_audit(self):
        engine = _Engine()
        first = _store("task-1", "parent-1", engine)
        self.assertTrue(first.v2_try_reserve_processed_taint("func-1", "msg[0]", json.dumps(["msg"]), "s1"))
        self.assertIn(("func-1", "msg[0]", "task-1"), engine.audit)

    def test_task_cleanup_releases_all_owned_claims(self):
        engine = _Engine()
        first = _store("task-1", "parent-1", engine)
        peer = _store("task-2", "parent-1", engine)
        self.assertTrue(first.v2_try_reserve_processed_taint("func-1", "msg[0]"))
        first.clear_task_analysis()
        self.assertTrue(peer.v2_try_reserve_processed_taint("func-1", "msg[0]"))


if __name__ == "__main__":
    unittest.main()
