"""Tests for core/llm_client.py — LM Studio preflight and timeout handling."""
import unittest
from unittest.mock import patch

import requests

from forcastl.core.llm_client import (
    LLMClient,
    attempt_lmstudio_load,
    check_lmstudio_model_state,
)


def _resp(status, payload):
    class R:
        status_code = status

        def json(self):
            return payload
    return R()


class LMStudioPreflightTests(unittest.TestCase):
    def test_v1_reports_loaded_when_instances_present(self):
        payload = {"models": [
            {"key": "foundation-sec-8b", "loaded_instances": ["i-1"]},
            {"key": "gemma-3-12b-it", "loaded_instances": []},
        ]}
        with patch("forcastl.core.llm_client.requests.get", return_value=_resp(200, payload)):
            self.assertEqual(
                check_lmstudio_model_state("http://x", "foundation-sec-8b"),
                "loaded",
            )

    def test_v1_reports_not_loaded_when_instances_empty(self):
        payload = {"models": [{"key": "m", "loaded_instances": []}]}
        with patch("forcastl.core.llm_client.requests.get", return_value=_resp(200, payload)):
            self.assertEqual(check_lmstudio_model_state("http://x", "m"), "not-loaded")

    def test_v1_returns_not_found_when_key_missing(self):
        payload = {"models": [{"key": "other", "loaded_instances": ["i-1"]}]}
        with patch("forcastl.core.llm_client.requests.get", return_value=_resp(200, payload)):
            self.assertEqual(check_lmstudio_model_state("http://x", "m"), "not-found")

    def test_falls_back_to_v0_when_v1_missing(self):
        v1 = _resp(404, {})
        v0 = _resp(200, {"data": [{"id": "m", "state": "loaded"}]})
        with patch("forcastl.core.llm_client.requests.get", side_effect=[v1, v0]) as mocked:
            state = check_lmstudio_model_state("http://x", "m")
        self.assertEqual(state, "loaded")
        self.assertEqual(mocked.call_count, 2)
        self.assertIn("/api/v1/models", mocked.call_args_list[0].args[0])
        self.assertIn("/api/v0/models", mocked.call_args_list[1].args[0])

    def test_falls_back_to_v0_when_v1_shape_mismatches(self):
        v1 = _resp(200, {"unexpected": True})
        v0 = _resp(200, {"data": [{"id": "m", "state": "not-loaded"}]})
        with patch("forcastl.core.llm_client.requests.get", side_effect=[v1, v0]):
            self.assertEqual(check_lmstudio_model_state("http://x", "m"), "not-loaded")

    def test_returns_none_when_shape_is_not_lmstudio(self):
        # OpenAI-compat shape has neither v1 nor v0 fields.
        payload = {"data": [{"id": "gpt-4", "object": "model"}]}
        with patch("forcastl.core.llm_client.requests.get", return_value=_resp(200, payload)):
            self.assertIsNone(check_lmstudio_model_state("http://x", "gpt-4"))

    def test_returns_none_on_connection_error(self):
        with patch("forcastl.core.llm_client.requests.get",
                   side_effect=requests.ConnectionError("nope")):
            self.assertIsNone(check_lmstudio_model_state("http://x", "m"))


class LMStudioAutoLoadTests(unittest.TestCase):
    """Auto-load via /api/v1/models/load when the preflight finds the model unloaded."""

    def test_returns_success_on_2xx(self):
        with patch("forcastl.core.llm_client.requests.post",
                   return_value=_resp(200, {"status": "ok"})):
            ok, err = attempt_lmstudio_load("http://x", "m")
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_returns_failure_when_endpoint_missing(self):
        with patch("forcastl.core.llm_client.requests.post",
                   return_value=_resp(404, {"error": {"message": "Unknown endpoint"}})):
            ok, err = attempt_lmstudio_load("http://x", "m")
        self.assertFalse(ok)
        self.assertIn("not supported", err)

    def test_returns_failure_with_upstream_detail(self):
        with patch("forcastl.core.llm_client.requests.post",
                   return_value=_resp(500, {"error": {"message": "out of VRAM"}})):
            ok, err = attempt_lmstudio_load("http://x", "m")
        self.assertFalse(ok)
        self.assertIn("out of VRAM", err)

    def test_returns_failure_on_connection_error(self):
        import requests as _rq
        with patch("forcastl.core.llm_client.requests.post",
                   side_effect=_rq.ConnectionError("nope")):
            ok, err = attempt_lmstudio_load("http://x", "m")
        self.assertFalse(ok)
        self.assertIn("nope", err)


class LLMClientPreflightTests(unittest.TestCase):
    def test_send_attempts_autoload_when_not_loaded(self):
        """If state is not-loaded, preflight calls attempt_lmstudio_load and
        proceeds when the load succeeds."""
        client = LLMClient(server_url="http://x", model_id="m", timeout=30, max_tokens=100)

        class OkResp:
            status_code = 200
            @staticmethod
            def json():
                return {"choices": [{"message": {"content": "hi"}}]}

        with patch("forcastl.core.llm_client.check_lmstudio_model_state",
                   side_effect=["not-loaded", "loaded"]):
            with patch("forcastl.core.llm_client.attempt_lmstudio_load",
                       return_value=(True, None)) as auto_load:
                with patch("forcastl.core.llm_client.requests.Session") as sess_cls:
                    sess_cls.return_value.post.return_value = OkResp()
                    text, _ = client.send_to_llm("hello")
        auto_load.assert_called_once()
        self.assertEqual(text, "hi")

    def test_send_returns_error_when_autoload_fails(self):
        """If auto-load fails, the request is not sent and a clean error is returned."""
        client = LLMClient(server_url="http://x", model_id="m", timeout=30, max_tokens=100)
        with patch("forcastl.core.llm_client.check_lmstudio_model_state", return_value="not-loaded"):
            with patch("forcastl.core.llm_client.attempt_lmstudio_load",
                       return_value=(False, "out of VRAM")):
                with patch("forcastl.core.llm_client.requests.Session") as sess_cls:
                    text, _ = client.send_to_llm("hello")
        self.assertIn("auto-load failed", text)
        self.assertIn("out of VRAM", text)
        sess_cls.assert_not_called()

    def test_send_returns_error_when_autoload_succeeds_but_state_doesnt_change(self):
        """LM Studio sometimes returns 200 from the load endpoint while the model
        hasn't actually finished loading. Surface that gracefully."""
        client = LLMClient(server_url="http://x", model_id="m", timeout=30, max_tokens=100)
        with patch("forcastl.core.llm_client.check_lmstudio_model_state",
                   side_effect=["not-loaded", "not-loaded"]):
            with patch("forcastl.core.llm_client.attempt_lmstudio_load", return_value=(True, None)):
                with patch("forcastl.core.llm_client.requests.Session") as sess_cls:
                    text, _ = client.send_to_llm("hello")
        self.assertIn("still reports state", text)
        sess_cls.assert_not_called()

    def test_send_returns_not_found_message(self):
        client = LLMClient(server_url="http://x", model_id="nope", timeout=30, max_tokens=100)
        with patch("forcastl.core.llm_client.check_lmstudio_model_state", return_value="not-found"):
            with patch("forcastl.core.llm_client.requests.Session") as sess_cls:
                text, _ = client.send_to_llm("hello")
        self.assertIn("not found on LM Studio", text)
        sess_cls.assert_not_called()

    def test_send_proceeds_when_state_loaded(self):
        client = LLMClient(server_url="http://x", model_id="m", timeout=30, max_tokens=100)

        class OkResp:
            status_code = 200

            @staticmethod
            def json():
                return {"choices": [{"message": {"content": "hi"}}]}

        with patch("forcastl.core.llm_client.check_lmstudio_model_state", return_value="loaded"):
            with patch("forcastl.core.llm_client.requests.Session") as sess_cls:
                sess_cls.return_value.post.return_value = OkResp()
                text, _ = client.send_to_llm("hello")
        self.assertEqual(text, "hi")

    def test_send_proceeds_when_not_lmstudio(self):
        client = LLMClient(server_url="http://x", model_id="m", timeout=30, max_tokens=100)

        class OkResp:
            status_code = 200

            @staticmethod
            def json():
                return {"choices": [{"message": {"content": "hi"}}]}

        with patch("forcastl.core.llm_client.check_lmstudio_model_state", return_value=None):
            with patch("forcastl.core.llm_client.requests.Session") as sess_cls:
                sess_cls.return_value.post.return_value = OkResp()
                text, _ = client.send_to_llm("hello")
        self.assertEqual(text, "hi")

    def test_preflight_runs_only_once_across_calls(self):
        client = LLMClient(server_url="http://x", model_id="m", timeout=30, max_tokens=100)

        class OkResp:
            status_code = 200

            @staticmethod
            def json():
                return {"choices": [{"message": {"content": "ok"}}]}

        with patch("forcastl.core.llm_client.check_lmstudio_model_state", return_value="loaded") as check:
            with patch("forcastl.core.llm_client.requests.Session") as sess_cls:
                sess = sess_cls.return_value
                sess.post.return_value = OkResp()
                client.send_to_llm("a")
                client.send_to_llm("b")
                client.send_to_llm("c")
        self.assertEqual(check.call_count, 1)


class WallClockDeadlineTests(unittest.TestCase):
    """Verify that self.timeout caps the entire send_to_llm call, including retries."""

    def _fast_client(self, timeout=2):
        c = LLMClient(server_url="http://x", model_id="m", timeout=timeout, max_tokens=100)
        # Skip LM Studio preflight for these tests.
        c._preflight_done = True
        return c

    def test_stuck_request_unblocked_by_watchdog(self):
        """A session.post that never returns should trip the watchdog and surface
        a wall-clock timeout message — not hang forever."""
        import time as _t
        client = self._fast_client(timeout=1)

        # Side effect: simulate a stuck recv by sleeping past the deadline.
        # The watchdog will fire session.close(); since we're mocking, detect it
        # and raise ConnectionError as the real requests library would.
        session_closed = {"flag": False}

        def hung_post(*a, **kw):
            # Block until session.close() is called, then raise.
            deadline = _t.time() + 10
            while _t.time() < deadline:
                if session_closed["flag"]:
                    raise requests.ConnectionError("session closed")
                _t.sleep(0.05)
            raise AssertionError("watchdog never fired")

        def fake_close(self=None):
            session_closed["flag"] = True

        with patch("forcastl.core.llm_client.requests.Session") as sess_cls:
            sess = sess_cls.return_value
            sess.post.side_effect = hung_post
            sess.close.side_effect = fake_close
            start = _t.time()
            text, elapsed = client.send_to_llm("prompt")
            total = _t.time() - start
        # Should complete in ~timeout + retry budget, not anywhere near 10s
        self.assertLess(total, 6, f"call took {total:.2f}s — watchdog didn't bound it")
        self.assertIn("timed out after 1s", text)

    def test_deadline_includes_retries(self):
        """3 retries must not push total wall-clock past the user-specified timeout."""
        import time as _t
        client = self._fast_client(timeout=2)

        def slow_post(*a, **kw):
            _t.sleep(1.0)  # each attempt eats 1s
            raise requests.ConnectionError("boom")

        with patch("forcastl.core.llm_client.requests.Session") as sess_cls:
            sess = sess_cls.return_value
            sess.post.side_effect = slow_post
            start = _t.time()
            text, _ = client.send_to_llm("prompt")
            elapsed = _t.time() - start
        # First attempt eats ~1s, leaves <1s remaining, second attempt should be
        # skipped by the "remaining <= 1.0" check. Total well under 3s.
        self.assertLess(elapsed, 3.5, f"retries extended deadline: {elapsed:.2f}s")
        self.assertIn("timed out", text)

    def test_success_short_circuits_watchdog(self):
        """A successful response cancels the watchdog and returns immediately."""
        client = self._fast_client(timeout=30)

        class OkResp:
            status_code = 200

            @staticmethod
            def json():
                return {"choices": [{"message": {"content": "done"}}]}

        with patch("forcastl.core.llm_client.requests.Session") as sess_cls:
            sess = sess_cls.return_value
            sess.post.return_value = OkResp()
            text, _ = client.send_to_llm("prompt")
        self.assertEqual(text, "done")
        sess.close.assert_called()  # session cleaned up


class LLMClientMaxTokensTests(unittest.TestCase):
    """The app must not impose a max_tokens cap unless one is explicitly set —
    the model server (LM Studio, etc.) governs output length."""

    class _OkResp:
        status_code = 200

        @staticmethod
        def json():
            return {"choices": [{"message": {"content": "hi"}}]}

    def _capture_payload(self, max_tokens):
        client = LLMClient(server_url="http://x", model_id="m", timeout=30,
                           max_tokens=max_tokens)
        with patch("forcastl.core.llm_client.check_lmstudio_model_state", return_value="loaded"):
            with patch("forcastl.core.llm_client.requests.Session") as sess_cls:
                sess_cls.return_value.post.return_value = self._OkResp()
                client.send_to_llm("hello")
                _, kwargs = sess_cls.return_value.post.call_args
        return kwargs["json"]

    def test_max_tokens_omitted_when_unset(self):
        payload = self._capture_payload(None)
        self.assertNotIn("max_tokens", payload)

    def test_max_tokens_sent_when_set(self):
        payload = self._capture_payload(256)
        self.assertEqual(payload["max_tokens"], 256)

    def test_default_constructor_leaves_max_tokens_unset(self):
        self.assertIsNone(LLMClient(server_url="http://x", model_id="m").max_tokens)


if __name__ == "__main__":
    unittest.main()
