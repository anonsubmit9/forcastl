"""OpenAI Chat Completions API client for FORCAST-L.

Mirrors core.llm_client.LLMClient's send_to_llm contract — returns
``(response_text, elapsed_seconds)`` and translates errors into ``"Error: ..."``
strings rather than raising.

The prompt is split into a static system message + a variable user message via
``split_simple_malicious_prompt``. OpenAI's automatic prompt caching kicks in
for prefixes ≥1024 tokens with no explicit cache_control — putting the static
instructions in the system message is sufficient. On the current FORCAST-L
prompt the prefix is ~430 tokens so caching will not fire today; the wiring is
correct so caching engages automatically once the prefix grows.
"""

import os
import time
from typing import Optional, Tuple

from forcastl.core.prompt import split_simple_malicious_prompt


class OpenAIClient:
    """Talks to the OpenAI Chat Completions API on behalf of FORCAST-L's detector."""

    def __init__(self, model_id: str, api_key: Optional[str] = None,
                 timeout: int = 120, max_tokens: Optional[int] = None,
                 temperature: float = 0.0):
        try:
            import openai
        except ImportError as e:
            raise RuntimeError(
                "openai SDK not installed. Add `openai>=1.50.0` to "
                "requirements.txt and run `pip install -r requirements.txt`."
            ) from e

        key = api_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            raise RuntimeError(
                "OpenAI API key not provided. Pass api_key=... or set "
                "OPENAI_API_KEY in the environment."
            )

        self._openai = openai
        self.client = openai.OpenAI(api_key=key, timeout=float(timeout))
        self.model_id = model_id
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.temperature = temperature

    def _uses_max_completion_tokens(self) -> bool:
        """O1/O3/O4 reasoning families and gpt-5 require max_completion_tokens."""
        m = self.model_id.lower()
        if m.startswith("gpt-5"):
            return True
        for prefix in ("o1", "o3", "o4"):
            if m.startswith(prefix):
                return True
        return False

    def send_to_llm(self, prompt: str) -> Tuple[str, float]:
        """Send the prompt and return ``(text, elapsed_seconds)``.

        Failures (auth, rate limits, connection errors, SDK-level timeout) are
        returned as ``"Error: ..."`` strings — never raised — so callers can
        treat the response uniformly with the LM Studio path.
        """
        start = time.time()
        openai = self._openai

        system_text, user_text = split_simple_malicious_prompt(prompt)
        messages = []
        if system_text:
            messages.append({"role": "system", "content": system_text})
        messages.append({"role": "user", "content": user_text})

        kwargs: dict = {
            "model": self.model_id,
            "messages": messages,
        }
        # Only cap output when explicitly requested; otherwise let the model/API
        # use its own default (we just send the prompt and document the result).
        if self.max_tokens is not None:
            if self._uses_max_completion_tokens():
                kwargs["max_completion_tokens"] = self.max_tokens
            else:
                kwargs["max_tokens"] = self.max_tokens
        # Match the LM Studio path (deterministic by default). Reasoning
        # families (o1/o3/o4, gpt-5) reject the temperature parameter, so they
        # keep the API default.
        if not self._uses_max_completion_tokens():
            kwargs["temperature"] = self.temperature

        try:
            response = self.client.chat.completions.create(**kwargs)

            usage = getattr(response, "usage", None)
            if usage is not None:
                try:
                    cached = 0
                    details = getattr(usage, "prompt_tokens_details", None)
                    if details is not None:
                        cached = getattr(details, "cached_tokens", 0) or 0
                    print(
                        f"[openai] tokens in={getattr(usage, 'prompt_tokens', 0)} "
                        f"out={getattr(usage, 'completion_tokens', 0)} "
                        f"cached={cached}",
                        flush=True,
                    )
                except Exception:
                    pass

            try:
                text = (response.choices[0].message.content or "").strip()
            except (AttributeError, IndexError, TypeError) as e:
                return f"Error: Malformed OpenAI response - {e}", time.time() - start

            if not text:
                return "Error: OpenAI API returned no text content", time.time() - start
            return text, time.time() - start

        except openai.AuthenticationError as e:
            return f"Error: OpenAI authentication failed - {e}", time.time() - start
        except openai.RateLimitError as e:
            return f"Error: OpenAI rate limit hit - {e}", time.time() - start
        except openai.BadRequestError as e:
            # Some newer models reject/deprecate `temperature`. We send it for
            # determinism on non-reasoning models, so drop it and retry once
            # rather than failing the run.
            if "temperature" in kwargs and "temperature" in str(e).lower():
                kwargs.pop("temperature", None)
                try:
                    response = self.client.chat.completions.create(**kwargs)
                    text = (response.choices[0].message.content or "").strip()
                    if not text:
                        return "Error: OpenAI API returned no text content", time.time() - start
                    return text, time.time() - start
                except Exception as e2:
                    return f"Error: OpenAI rejected the request - {e2}", time.time() - start
            return f"Error: OpenAI rejected the request - {e}", time.time() - start
        except openai.APITimeoutError:
            return f"Error: Request timed out after {self.timeout}s", time.time() - start
        except openai.APIConnectionError as e:
            return f"Error: Could not connect to OpenAI API - {e}", time.time() - start
        except openai.APIStatusError as e:
            return (f"Error: OpenAI API error {getattr(e, 'status_code', '?')} - {e}",
                    time.time() - start)
        except Exception as e:
            return f"Error: {e}", time.time() - start


_OPENAI_SKIP_KEYWORDS = (
    "embedding", "embed", "whisper", "tts", "dall-e", "dalle", "moderation",
    "babbage", "ada-", "davinci", "curie", "image", "audio", "speech", "realtime",
    "search", "transcribe",
)


def list_openai_models(api_key: Optional[str] = None,
                       timeout: float = 10.0) -> list:
    """Best-effort: query OpenAI's /v1/models endpoint and return chat-capable
    models. Returns ``[]`` on auth/network failure so callers can fall back.
    """
    try:
        import openai
    except ImportError:
        return []
    key = api_key or os.environ.get("OPENAI_API_KEY")
    if not key:
        return []
    try:
        client = openai.OpenAI(api_key=key, timeout=timeout)
        page = client.models.list()
        models = []
        for m in page.data:
            mid = getattr(m, "id", "")
            if not mid:
                continue
            lower = mid.lower()
            if any(skip in lower for skip in _OPENAI_SKIP_KEYWORDS):
                continue
            is_chat = (
                lower.startswith("gpt-")
                or lower.startswith("chatgpt-")
                or any(lower.startswith(f"o{n}") for n in range(1, 10))
            )
            if is_chat:
                models.append({"id": mid, "name": mid})
        # Stable, dedup'd alphabetical sort.
        seen = set()
        unique = []
        for m in sorted(models, key=lambda x: x["id"]):
            if m["id"] in seen:
                continue
            seen.add(m["id"])
            unique.append(m)
        return unique
    except Exception:
        return []
