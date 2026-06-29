import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.event_adapter import coerce_swarm_event
from app.models import SwarmEvent


class EventAdapterTests(unittest.TestCase):
    def test_accepts_swarm_event_passthrough(self):
        event = SwarmEvent(type="task_start", task_id="dvs_1", data={"k": "v"})
        self.assertIs(event, coerce_swarm_event(event, default_task_id="fallback"))

    def test_accepts_keyword_style_event(self):
        event = coerce_swarm_event(
            task_id="dvs_2",
            event_type="v2_run_started",
            function="root",
            default_task_id="fallback",
        )
        self.assertEqual("v2_run_started", event.type)
        self.assertEqual("dvs_2", event.task_id)
        self.assertEqual({"function": "root"}, event.data)

    def test_accepts_string_event_type_plus_kwargs(self):
        event = coerce_swarm_event(
            "workspace_localized",
            task_id="dvs_3",
            local_path="/tmp/local",
            default_task_id="fallback",
        )
        self.assertEqual("workspace_localized", event.type)
        self.assertEqual("dvs_3", event.task_id)
        self.assertEqual({"local_path": "/tmp/local"}, event.data)

    def test_uses_default_task_id_when_not_provided(self):
        event = coerce_swarm_event("workspace_synced", status="completed", default_task_id="dvs_4")
        self.assertEqual("dvs_4", event.task_id)
        self.assertEqual("workspace_synced", event.type)
        self.assertEqual({"status": "completed"}, event.data)


if __name__ == "__main__":
    unittest.main()
