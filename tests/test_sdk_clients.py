"""Request-construction tests for the Anthropic/OpenAI clients.

These pin the 2026-06-09 temperature unification (send 0.0 by default, with the
API-forbidden carve-outs) and the max-tokens routing, without any real API
call: a fake SDK client captures the kwargs each client builds.
"""
import types
import unittest

from forcastl.core.openai_client import OpenAIClient
from forcastl.core.anthropic_client import AnthropicClient


# ── OpenAI harness ────────────────────────────────────────────────────────────

def _openai_client(model, max_tokens=None, temperature=0.0):
    c = OpenAIClient.__new__(OpenAIClient)
    c._openai = types.SimpleNamespace()   # never touched unless an exception propagates
    c.model_id = model
    c.timeout = 30
    c.max_tokens = max_tokens
    c.temperature = temperature
    captured = {}

    def create(**kwargs):
        captured.update(kwargs)
        msg = types.SimpleNamespace(content="MALICIOUS: NO")
        return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)], usage=None)

    c.client = types.SimpleNamespace(
        chat=types.SimpleNamespace(completions=types.SimpleNamespace(create=create)))
    return c, captured


class OpenAIRequestTests(unittest.TestCase):
    def test_non_reasoning_sends_temperature_zero(self):
        c, kw = _openai_client("gpt-4o")
        c.send_to_llm("DATA")
        self.assertEqual(kw["temperature"], 0.0)

    def test_custom_temperature_passed_through(self):
        c, kw = _openai_client("gpt-4o", temperature=0.7)
        c.send_to_llm("DATA")
        self.assertEqual(kw["temperature"], 0.7)

    def test_reasoning_family_omits_temperature(self):
        for model in ("gpt-5.5", "o1-preview", "o3-mini", "o4"):
            c, kw = _openai_client(model)
            c.send_to_llm("DATA")
            self.assertNotIn("temperature", kw, f"{model} must not send temperature")

    def test_max_tokens_routing(self):
        # Non-reasoning → max_tokens; reasoning → max_completion_tokens.
        c, kw = _openai_client("gpt-4o", max_tokens=500)
        c.send_to_llm("DATA")
        self.assertEqual(kw.get("max_tokens"), 500)
        self.assertNotIn("max_completion_tokens", kw)

        c, kw = _openai_client("gpt-5.5", max_tokens=500)
        c.send_to_llm("DATA")
        self.assertEqual(kw.get("max_completion_tokens"), 500)
        self.assertNotIn("max_tokens", kw)

    def test_max_tokens_omitted_when_unset(self):
        c, kw = _openai_client("gpt-4o", max_tokens=None)
        c.send_to_llm("DATA")
        self.assertNotIn("max_tokens", kw)
        self.assertNotIn("max_completion_tokens", kw)


# ── Anthropic harness ─────────────────────────────────────────────────────────

def _anthropic_client(model, thinking=False, max_tokens=None, temperature=0.0):
    c = AnthropicClient.__new__(AnthropicClient)
    c._anthropic = types.SimpleNamespace()
    c.model_id = model
    c.timeout = 30
    c.max_tokens = max_tokens
    c.thinking = thinking
    c.temperature = temperature
    captured = {}

    final = types.SimpleNamespace(
        content=[types.SimpleNamespace(type="text", text="MALICIOUS: NO")], usage=None)

    class _Stream:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get_final_message(self): return final
        def close(self): pass

    def stream(**kwargs):
        captured.update(kwargs)
        return _Stream()

    c.client = types.SimpleNamespace(messages=types.SimpleNamespace(stream=stream))
    return c, captured


class AnthropicRequestTests(unittest.TestCase):
    def test_default_sends_temperature_zero(self):
        c, kw = _anthropic_client("claude-opus-4-8")
        c.send_to_llm("DATA")
        self.assertEqual(kw["temperature"], 0.0)

    def test_thinking_omits_temperature_and_adds_thinking(self):
        # Extended thinking is mutually exclusive with temperature.
        c, kw = _anthropic_client("claude-opus-4-8", thinking=True)
        c.send_to_llm("DATA")
        self.assertNotIn("temperature", kw)
        self.assertEqual(kw["thinking"], {"type": "adaptive"})

    def test_max_tokens_defaults_to_8192_when_unset(self):
        c, kw = _anthropic_client("claude-opus-4-8", max_tokens=None)
        c.send_to_llm("DATA")
        self.assertEqual(kw["max_tokens"], 8192)   # API requires the field

    def test_max_tokens_passed_when_set(self):
        c, kw = _anthropic_client("claude-opus-4-8", max_tokens=1000)
        c.send_to_llm("DATA")
        self.assertEqual(kw["max_tokens"], 1000)

    def test_system_block_split_with_cache_control(self):
        # A real prompt carries the cache markers → static prefix goes to a
        # cache-eligible system block.
        from forcastl.core.prompt import PromptManager
        prompt = PromptManager().generate_simple_malicious_prompt("<Event/>")
        c, kw = _anthropic_client("claude-opus-4-8")
        c.send_to_llm(prompt)
        self.assertIn("system", kw)
        self.assertEqual(kw["system"][0]["cache_control"], {"type": "ephemeral"})


# ── retry-without-temperature on deprecation (regression for the 2026-06-10 bug) ──

def _exc_ns(names):
    ns = types.SimpleNamespace()
    for n in names:
        setattr(ns, n, type(n, (Exception,), {}))
    return ns


_ANTHROPIC_EXC = ("AuthenticationError", "RateLimitError", "BadRequestError",
                  "APIConnectionError", "APIStatusError")
_OPENAI_EXC = ("AuthenticationError", "RateLimitError", "BadRequestError",
               "APITimeoutError", "APIConnectionError", "APIStatusError")


class TemperatureDeprecationRetryTests(unittest.TestCase):
    """A model that rejects `temperature` (newer Claude/OpenAI) must not fail the
    run — the client drops the param and retries once."""

    def _anthropic_with_stream(self, stream_fn):
        exc = _exc_ns(_ANTHROPIC_EXC)
        c = AnthropicClient.__new__(AnthropicClient)
        c._anthropic = exc
        c.model_id = "claude-opus-4-8"
        c.timeout = 30
        c.max_tokens = None
        c.thinking = False
        c.temperature = 0.0
        c.client = types.SimpleNamespace(messages=types.SimpleNamespace(stream=stream_fn))
        return c, exc

    def test_anthropic_retries_without_temperature(self):
        calls = []
        final = types.SimpleNamespace(
            content=[types.SimpleNamespace(type="text", text="MALICIOUS: NO")], usage=None)

        class _Stream:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def get_final_message(self): return final
            def close(self): pass

        def stream(**kwargs):
            calls.append(dict(kwargs))
            if len(calls) == 1:
                raise exc.BadRequestError("400 - `temperature` is deprecated for this model.")
            return _Stream()

        c, exc = self._anthropic_with_stream(stream)
        text, _ = c.send_to_llm("DATA")
        self.assertEqual(text, "MALICIOUS: NO")
        self.assertEqual(len(calls), 2)
        self.assertIn("temperature", calls[0])       # first attempt sent it
        self.assertNotIn("temperature", calls[1])     # retry dropped it

    def test_anthropic_non_temperature_400_does_not_retry(self):
        calls = []

        def stream(**kwargs):
            calls.append(dict(kwargs))
            raise exc.BadRequestError("400 - max_tokens too large")

        c, exc = self._anthropic_with_stream(stream)
        text, _ = c.send_to_llm("DATA")
        self.assertTrue(text.startswith("Error: Anthropic rejected"))
        self.assertEqual(len(calls), 1)               # no retry on unrelated 400

    def _openai_with_create(self, create_fn):
        exc = _exc_ns(_OPENAI_EXC)
        c = OpenAIClient.__new__(OpenAIClient)
        c._openai = exc
        c.model_id = "gpt-4o"
        c.timeout = 30
        c.max_tokens = None
        c.temperature = 0.0
        c.client = types.SimpleNamespace(
            chat=types.SimpleNamespace(completions=types.SimpleNamespace(create=create_fn)))
        return c, exc

    def test_openai_retries_without_temperature(self):
        calls = []

        def create(**kwargs):
            calls.append(dict(kwargs))
            if len(calls) == 1:
                raise exc.BadRequestError("400 - Unsupported parameter: 'temperature' is deprecated")
            msg = types.SimpleNamespace(content="MALICIOUS: NO")
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)], usage=None)

        c, exc = self._openai_with_create(create)
        text, _ = c.send_to_llm("DATA")
        self.assertEqual(text, "MALICIOUS: NO")
        self.assertEqual(len(calls), 2)
        self.assertIn("temperature", calls[0])
        self.assertNotIn("temperature", calls[1])


if __name__ == "__main__":
    unittest.main()
