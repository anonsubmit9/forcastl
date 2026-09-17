"""Anthropic Messages API client for FORCAST-L.

Mirrors core.llm_client.LLMClient's send_to_llm contract — returns
``(response_text, elapsed_seconds)`` and translates errors into ``"Error: ..."``
strings rather than raising.

The prompt is split into a static system block (cache-eligible) and a variable
user block (the XML payload) so prompt caching activates automatically once the
static prefix exceeds the provider's minimum (4096 tokens for Opus). On the
current FORCAST-L prompt the prefix is ~430 tokens and caching will not fire —
the wiring is correct so caching kicks in for free when the prefix grows.
"""

import os
import threading
import time
from typing import Optional, Tuple

from forcastl.core.prompt import split_simple_malicious_prompt


class AnthropicClient:
    """Talks to the Anthropic Messages API on behalf of FORCAST-L's detector."""

    def __init__(self, model_id: str, api_key: Optional[str] = None,
                 timeout: int = 120, max_tokens: Optional[int] = None,
                 thinking: bool = False, temperature: float = 0.0):
        try:
            import anthropic
        except ImportError as e:
            raise RuntimeError(
                "anthropic SDK not installed. Add `anthropic>=0.40.0` to "
                "requirements.txt and run `pip install -r requirements.txt`."
            ) from e

        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError(
                "Anthropic API key not provided. Pass api_key=... or set "
                "ANTHROPIC_API_KEY in the environment."
            )

        self._anthropic = anthropic
        self.client = anthropic.Anthropic(api_key=key)
        self.model_id = model_id
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.thinking = thinking
        self.temperature = temperature

    def _stream_text(self, kwargs: dict, stream_holder: dict) -> str:
        """Run one streamed Messages call and return the concatenated text.

        Raises the SDK's exceptions (auth/rate-limit/bad-request/…) so the
        caller can map them; the caller also retries this without
        ``temperature`` if the model rejects that parameter.
        """
        with self.client.messages.stream(**kwargs) as stream:
            stream_holder["stream"] = stream
            final_message = stream.get_final_message()

        usage = getattr(final_message, "usage", None)
        if usage is not None:
            try:
                print(
                    f"[anthropic] tokens in={getattr(usage, 'input_tokens', 0)} "
                    f"out={getattr(usage, 'output_tokens', 0)} "
                    f"cache_read={getattr(usage, 'cache_read_input_tokens', 0)} "
                    f"cache_write={getattr(usage, 'cache_creation_input_tokens', 0)}",
                    flush=True,
                )
            except Exception:
                pass

        parts = []
        for block in final_message.content:
            if getattr(block, "type", None) == "text":
                parts.append(block.text)
        return "".join(parts).strip()

    def send_to_llm(self, prompt: str) -> Tuple[str, float]:
        """Send the prompt and return ``(text, elapsed_seconds)``.

        Failures (auth, rate limits, connection errors, watchdog timeout) are
        returned as ``"Error: ..."`` strings — never raised — so callers can
        treat the response uniformly with the LM Studio path.
        """
        start = time.time()
        anthropic = self._anthropic

        system_text, user_text = split_simple_malicious_prompt(prompt)

        kwargs: dict = {
            "model": self.model_id,
            # Anthropic's API *requires* max_tokens, so unlike the OpenAI-compatible
            # path we can't omit it. When the caller didn't impose a cap, use a
            # generous default so we don't truncate the response.
            "max_tokens": self.max_tokens if self.max_tokens is not None else 8192,
            "messages": [{"role": "user", "content": user_text}],
        }
        if system_text:
            kwargs["system"] = [
                {
                    "type": "text",
                    "text": system_text,
                    "cache_control": {"type": "ephemeral"},
                }
            ]
        if self.thinking:
            # Extended thinking requires the API's default temperature — the
            # two settings are mutually exclusive, so thinking wins here.
            kwargs["thinking"] = {"type": "adaptive"}
        else:
            # Match the LM Studio path (deterministic by default) instead of
            # silently falling back to the SDK default of 1.0.
            kwargs["temperature"] = self.temperature

        watchdog_fired = threading.Event()
        stream_holder = {"stream": None}

        def _force_close():
            watchdog_fired.set()
            s = stream_holder.get("stream")
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

        watchdog = threading.Timer(self.timeout, _force_close)
        watchdog.daemon = True
        watchdog.start()

        try:
            text = self._stream_text(kwargs, stream_holder)
            if not text:
                return "Error: Anthropic API returned no text content", time.time() - start
            return text, time.time() - start

        except anthropic.AuthenticationError as e:
            return f"Error: Anthropic authentication failed - {e}", time.time() - start
        except anthropic.RateLimitError as e:
            return f"Error: Anthropic rate limit hit - {e}", time.time() - start
        except anthropic.BadRequestError as e:
            # Newer Claude models reject `temperature` outright ("temperature is
            # deprecated for this model"). We send 0.0 for determinism by
            # default, so drop it and retry once rather than failing the run.
            if "temperature" in kwargs and "temperature" in str(e).lower():
                kwargs.pop("temperature", None)
                try:
                    text = self._stream_text(kwargs, stream_holder)
                    if not text:
                        return "Error: Anthropic API returned no text content", time.time() - start
                    return text, time.time() - start
                except Exception as e2:
                    return f"Error: Anthropic rejected the request - {e2}", time.time() - start
            return f"Error: Anthropic rejected the request - {e}", time.time() - start
        except anthropic.APIConnectionError as e:
            if watchdog_fired.is_set():
                return f"Error: Request timed out after {self.timeout}s", time.time() - start
            return f"Error: Could not connect to Anthropic API - {e}", time.time() - start
        except anthropic.APIStatusError as e:
            return (f"Error: Anthropic API error {getattr(e, 'status_code', '?')} - {e}",
                    time.time() - start)
        except Exception as e:
            if watchdog_fired.is_set():
                return f"Error: Request timed out after {self.timeout}s", time.time() - start
            return f"Error: {e}", time.time() - start
        finally:
            watchdog.cancel()


def list_anthropic_models(api_key: Optional[str] = None,
                          timeout: float = 10.0) -> list:
    """Best-effort: query Anthropic's /v1/models endpoint and return the list.

    Returns ``[]`` on auth/network failure so the webapp can degrade gracefully
    to a static fallback list.
    """
    try:
        import anthropic
    except ImportError:
        return []
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return []
    try:
        client = anthropic.Anthropic(api_key=key, timeout=timeout)
        page = client.models.list(limit=100)
        return [{"id": m.id, "name": getattr(m, "display_name", m.id)} for m in page.data]
    except Exception:
        return []
