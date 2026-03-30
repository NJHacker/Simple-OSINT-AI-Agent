from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    anthropic_api_key: str
    anthropic_model: str
    search_backend: str
    max_agent_steps: int
    output_dir: Path
    action_max_tokens: int
    report_max_tokens: int
    temperature: float


def load_settings() -> Settings:
    load_dotenv()

    anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    anthropic_model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6").strip()
    search_backend = os.getenv("SEARCH_BACKEND", "mock").strip().lower()
    max_agent_steps = int(os.getenv("MAX_AGENT_STEPS", "8"))
    output_dir = Path(os.getenv("OUTPUT_DIR", "reports")).resolve()
    action_max_tokens = int(os.getenv("ACTION_MAX_TOKENS", "1200"))
    report_max_tokens = int(os.getenv("REPORT_MAX_TOKENS", "2500"))
    temperature = float(os.getenv("TEMPERATURE", "0.2"))

    if not anthropic_api_key:
        raise ValueError(
            "ANTHROPIC_API_KEY is missing. Add it to your local .env file."
        )

    return Settings(
        anthropic_api_key=anthropic_api_key,
        anthropic_model=anthropic_model,
        search_backend=search_backend,
        max_agent_steps=max_agent_steps,
        output_dir=output_dir,
        action_max_tokens=action_max_tokens,
        report_max_tokens=report_max_tokens,
        temperature=temperature,
    )