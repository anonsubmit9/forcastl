"""Shared OpenAI-compatible inference for benchmark runners."""

from __future__ import annotations

from typing import Tuple

from forcastl.core.llm_client import LLMClient


def complete_openai_compatible(
    *,
    server_url: str,
    model: str,
    prompt: str,
    timeout: int,
    max_tokens: int,
    temperature: float = 0.0,
) -> Tuple[str, float]:
    """Send a single user prompt; return (response_text, response_time_s)."""
    client = LLMClient(
        server_url=server_url,
        model_id=model,
        timeout=timeout,
        max_tokens=max_tokens,
    )
    return client.send_to_llm(prompt, temperature=temperature)
