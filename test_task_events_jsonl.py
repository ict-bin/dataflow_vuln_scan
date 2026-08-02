from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from app.db.models import AppDvsTask
from app.service.task_events import (
    _record_task_event,
    _task_events_path,
    append_task_event,
    clear_task_events,
    delete_task_event,
    read_task_event_responses,
    read_task_events,
    read_task_events_tail,
    task_events_lock_path,
)


class TaskEventsJsonlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.row = AppDvsTask(
            task_id="dvs_events_jsonl",
            project_id="project-events",
            task_name="events",
            input_path="/input",
            output_path=self.temp_dir.name,
            prompt_content="analyse",
            status="running",
            execution_epoch=3,
            control_version=4,
            dispatch_status="running",
        )

    def test_record_appends_duplicate_events_without_deduplication(self) -> None:
        first = _record_task_event(None, row=self.row, event_type="heartbeat", message="same", payload={"items": [1, 2]})
        second = _record_task_event(None, row=self.row, event_type="heartbeat", message="same", payload={"items": [1, 2]})

        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertNotEqual(first["id"], second["id"])
        events = read_task_events(self.row, newest_first=False)
        self.assertEqual(2, len(events))
        self.assertEqual(["same", "same"], [event["message"] for event in events])
        self.assertEqual([1, 2], events[0]["payload"]["items"])

    def test_parallel_append_keeps_each_json_line(self) -> None:
        count = 40
        barrier = threading.Barrier(count)

        def write_event(index: int) -> None:
            barrier.wait()
            append_task_event(self.row, {"id": f"e-{index}", "created_at": f"2026-08-02T00:00:{index:02d}", "event_type": "parallel"})

        threads = [threading.Thread(target=write_event, args=(index,)) for index in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        path = _task_events_path(self.row)
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
        self.assertEqual(count, len(lines))
        self.assertEqual(count, len({json.loads(line)["id"] for line in lines}))
        self.assertTrue(task_events_lock_path(_task_events_path(self.row).parent.parent).exists())
        self.assertFalse((_task_events_path(self.row).parent / ".events.jsonl.lock").exists())

    def test_reader_skips_malformed_line_and_tail_is_in_time_order(self) -> None:
        append_task_event(self.row, {"id": "first", "created_at": "2026-08-02T00:00:01", "event_type": "one"})
        path = _task_events_path(self.row)
        with path.open("a", encoding="utf-8") as handle:
            handle.write("not-json\n")
        append_task_event(self.row, {"id": "last", "created_at": "2026-08-02T00:00:03", "event_type": "three"})

        responses = read_task_event_responses(self.row)
        self.assertEqual(["last", "first"], [item["id"] for item in responses])
        tail = read_task_events_tail(self.row, 2)
        self.assertEqual(["first", "last"], [item["id"] for item in tail])

    def test_delete_and_clear_keep_api_level_semantics(self) -> None:
        append_task_event(self.row, {"id": "keep", "created_at": "2026-08-02T00:00:01", "event_type": "one"})
        append_task_event(self.row, {"id": "remove", "created_at": "2026-08-02T00:00:02", "event_type": "two"})

        self.assertEqual(1, delete_task_event(self.row, "remove"))
        self.assertEqual(["keep"], [item["id"] for item in read_task_events(self.row)])
        self.assertEqual(1, clear_task_events(self.row))
        self.assertEqual([], read_task_events(self.row))

    def test_write_failure_is_nonfatal(self) -> None:
        with patch("app.service.task_events.append_task_event", side_effect=OSError("nfs unavailable")):
            self.assertIsNone(_record_task_event(None, row=self.row, event_type="write_failed", message="event"))


if __name__ == "__main__":
    unittest.main()
