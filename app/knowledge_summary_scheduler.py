"""Leader-elected scheduler for DVS vulnerability knowledge summaries."""

from __future__ import annotations

import signal

from app.config import get_service_yaml
from app.db import init_db
from app.service.knowledge_summary import get_knowledge_summary_service


def main() -> None:
    config = get_service_yaml()
    init_db(config.database.url, config.database.pool_size, config.database.max_overflow)
    service = get_knowledge_summary_service()
    signal.signal(signal.SIGTERM, lambda *_: service.stop())
    signal.signal(signal.SIGINT, lambda *_: service.stop())
    service.run_forever()


if __name__ == "__main__":
    main()
