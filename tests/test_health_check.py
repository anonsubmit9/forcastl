"""Offline tests for core/health_check.py — no real API calls.

Patches the lazily-imported clients / LM Studio state probe so each status path is
exercised without network access.
"""
import unittest
from unittest.mock import patch

from forcastl.core.health_check import health_check, HARD_FAIL

VALID = ("MALICIOUS: NO\n\nEVIDENCE:\n- Event IDs: 4624\n\nEXPLANATION: routine login.", 1.2)


class _FakeClient:
    def __init__(self, ret):
        self._ret = ret

    def send_to_llm(self, prompt, **kw):
        return self._ret


def _lmstudio(ret, state="loaded", **kw):
    with patch("forcastl.core.llm_client.check_lmstudio_model_state", return_value=state), \
         patch("forcastl.core.llm_client.LLMClient", return_value=_FakeClient(ret)):
        return health_check("lmstudio", server="http://x:1234", model="m", **kw)


class LMStudioHealthChecks(unittest.TestCase):
    def test_ok(self):
        r = _lmstudio(VALID)
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["latency_s"], 1.2)
        self.assertNotIn(r["status"], HARD_FAIL)

    def test_no_verdict_is_soft(self):
        r = _lmstudio(("Sure, that log looks fine to me!", 0.8))
        self.assertEqual(r["status"], "no_verdict")
        self.assertNotIn(r["status"], HARD_FAIL)

    def test_unreachable(self):
        r = _lmstudio(("Error: Could not connect to server", 0.0))
        self.assertEqual(r["status"], "unreachable")
        self.assertIn(r["status"], HARD_FAIL)

    def test_timeout(self):
        r = _lmstudio(("Error: Request timed out after 60s", 60.0))
        self.assertEqual(r["status"], "timeout")

    def test_model_not_found_fast_path(self):
        with patch("forcastl.core.llm_client.check_lmstudio_model_state", return_value="not-found"):
            r = health_check("lmstudio", server="http://x:1234", model="nope")
        self.assertEqual(r["status"], "model_not_found")


class ApiProviderHealthChecks(unittest.TestCase):
    def test_openai_ok(self):
        with patch("forcastl.core.openai_client.OpenAIClient", return_value=_FakeClient(VALID)):
            r = health_check("openai", model="gpt-x", api_key="sk-test")
        self.assertEqual(r["status"], "ok")

    def test_openai_auth_error_string(self):
        bad = ("Error: OpenAI authentication failed - invalid api key", 0.0)
        with patch("forcastl.core.openai_client.OpenAIClient", return_value=_FakeClient(bad)):
            r = health_check("openai", model="gpt-x", api_key="bad")
        self.assertEqual(r["status"], "auth_failed")

    def test_anthropic_missing_key_is_auth_failed(self):
        with patch("forcastl.core.anthropic_client.AnthropicClient",
                   side_effect=RuntimeError("Anthropic API key not provided")):
            r = health_check("anthropic", model="claude-x", api_key=None)
        self.assertEqual(r["status"], "auth_failed")


class ConfigGuards(unittest.TestCase):
    def test_no_model(self):
        r = health_check("lmstudio", server="http://x", model="")
        self.assertEqual(r["status"], "invalid_config")


if __name__ == "__main__":
    unittest.main()
