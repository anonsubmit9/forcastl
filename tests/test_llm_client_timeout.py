"""LLMClient.send_to_llm must honour --timeout as a hard wall-clock cap, even
when the server is far slower than the deadline (the bug: a long non-streaming
generation ran ~1995s under a 300s timeout). Verified against a local mock HTTP
server — no real model, no tokens."""
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from forcastl.core.llm_client import LLMClient


class _Handler(BaseHTTPRequestHandler):
    sleep_s = 0.0

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):  # /api/v*/models preflight probes -> not LM Studio
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        ln = int(self.headers.get("Content-Length", 0) or 0)
        if ln:
            self.rfile.read(ln)
        time.sleep(type(self).sleep_s)
        body = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestHardTimeout(unittest.TestCase):
    def setUp(self):
        _Handler.sleep_s = 0.0
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.srv.daemon_threads = True
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def _client(self, timeout):
        return LLMClient(f"http://127.0.0.1:{self.port}", "m",
                         timeout=timeout, max_tokens=10)

    def test_normal_response(self):
        txt, _ = self._client(5).send_to_llm("hi")
        self.assertEqual(txt, "ok")

    def test_hard_timeout_is_enforced(self):
        _Handler.sleep_s = 4.0          # server far slower than the 1s deadline
        client = self._client(1)
        t0 = time.time()
        txt, _ = client.send_to_llm("hi")
        elapsed = time.time() - t0
        self.assertIn("timed out after 1s", txt)
        self.assertLess(elapsed, 2.5, f"timeout not enforced — took {elapsed:.1f}s")

    def test_timeout_is_a_hard_cap_no_silent_extension(self):
        # Large prompt must NOT extend the budget beyond the configured timeout.
        self.assertEqual(self._client(42)._total_budget("x" * 100000), 42.0)


if __name__ == "__main__":
    unittest.main()
