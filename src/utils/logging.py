from __future__ import annotations

import logging
from pathlib import Path


def setup_logging(log_file: Path) -> None:
    logger = logging.getLogger("simple_ai_agent")
    if logger.handlers:
        return

    logger.setLevel(logging.INFO)

    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    )

    logger.addHandler(handler)