from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def create_timestamped_run_dir(base_dir: str | Path) -> Path:
    root = Path(base_dir)
    root.mkdir(parents=True, exist_ok=True)

    run_dir = root / datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def read_json(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str | Path, payload: Any) -> None:
    file_path = Path(path)
    ensure_parent_dir(file_path)
    with file_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def write_text(path: str | Path, content: str) -> None:
    file_path = Path(path)
    ensure_parent_dir(file_path)
    with file_path.open("w", encoding="utf-8") as f:
        f.write(content)