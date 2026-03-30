import json
import logging
import time
from typing import TypeVar

import anthropic
from pydantic import BaseModel, ValidationError

from src.utils.config import Settings

T = TypeVar("T", bound=BaseModel)


class ClaudeClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        self.logger = logging.getLogger("simple_ai_agent.llm")

    def generate_text(
            self,
            *,
            system_prompt: str,
            user_prompt: str,
            max_tokens: int | None = None,
            temperature: float | None = None,
    ) -> str:
        start = time.perf_counter()

        response = self.client.messages.create(
            model=self.settings.anthropic_model,
            max_tokens=max_tokens or self.settings.action_max_tokens,
            temperature=self.settings.temperature if temperature is None else temperature,
            system=system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": user_prompt,
                }
            ],
        )

        text = self._extract_text(response)

        self.logger.info(
            "Claude call completed | chars=%s | elapsed=%.2fs | stop_reason=%s",
            len(text),
            time.perf_counter() - start,
            getattr(response, "stop_reason", None),
        )
        return text

    def generate_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_model: type[T],
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> T:
        raw_text = self.generate_text(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        json_text = self._extract_json_block(raw_text)

        try:
            payload = json.loads(json_text)
        except json.JSONDecodeError as exc:
            debug_path = self.settings.output_dir / "last_invalid_json.txt"
            debug_path.write_text(raw_text, encoding="utf-8")

            self.logger.exception(
                "Claude returned invalid JSON. Raw response saved to %s",
                debug_path,
            )

            raise ValueError(
                f"Claude returned invalid JSON. Raw response saved to: {debug_path}"
            ) from exc

        try:
            return response_model.model_validate(payload)
        except ValidationError as exc:
            raise ValueError(
                f"Claude JSON did not match expected schema {response_model.__name__}.\n"
                f"Payload:\n{json.dumps(payload, indent=2, ensure_ascii=False)}"
            ) from exc

    @staticmethod
    def _extract_text(response: anthropic.types.Message) -> str:
        text_parts: list[str] = []

        for block in response.content:
            block_type = getattr(block, "type", None)
            if block_type == "text":
                text_parts.append(block.text)

        if not text_parts:
            raise ValueError("Claude response did not contain any text blocks.")

        return "\n".join(text_parts).strip()

    @staticmethod
    def _extract_json_block(text: str) -> str:
        stripped = text.strip()

        if stripped.startswith("```json"):
            stripped = stripped.removeprefix("```json").strip()
        elif stripped.startswith("```"):
            stripped = stripped.removeprefix("```").strip()

        if stripped.endswith("```"):
            stripped = stripped[:-3].strip()

        return stripped