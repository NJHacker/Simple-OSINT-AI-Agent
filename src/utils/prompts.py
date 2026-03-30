from __future__ import annotations

from pathlib import Path


_PROMPTS_DIR = Path(__file__).resolve().parents[1] / "prompts"


def load_prompt(name: str, **kwargs: str) -> str:
    prompt_path = _PROMPTS_DIR / name
    template = prompt_path.read_text(encoding="utf-8")

    for key, value in kwargs.items():
        template = template.replace(f"{{{{{key}}}}}", value)

    return template