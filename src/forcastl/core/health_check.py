"""Pre-flight health check — verify a model is usable BEFORE a long run.

One shared check across providers (``lmstudio`` / ``anthropic`` / ``openai``). It sends a
single minimal test prompt through the *real* detection-prompt format and confirms the
model is reachable, authenticated, and returns a ``MALICIOUS:`` verdict — so a wrong model
id, bad API key, unreachable server, or a model that can't follow the format is caught up
front instead of failing every file of a 2-hour run.

Reuses the existing clients and helpers; it does not re-implement reachability or parsing.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from forcastl.core.response_parser import is_incomplete_response

# A trivial instruction-following probe — NOT a real analysis. Asking the model to *analyse*
# a near-empty artefact makes reasoning models ramble for minutes; a health check only needs
# to confirm the model is reachable, authenticated, and can emit the `MALICIOUS:` line. We do
# not cap max_tokens (let the server govern, like a real run).
_HEALTH_PROMPT = (
    "You are a forensic triage assistant. This is a connectivity health check, not a real "
    "analysis — do not reason at length. Reply with EXACTLY these two lines and nothing else:\n"
    "MALICIOUS: NO\n"
    "EXPLANATION: health check ok"
)

# Statuses that mean the model genuinely can't be used. `timeout` is deliberately NOT
# here: a slow (e.g. reasoning) model can exceed the probe budget on the tiny artefact yet
# still run fine under a higher per-file --timeout, so it's a soft warning, not a block.
HARD_FAIL = {"unreachable", "auth_failed", "model_not_found", "error", "invalid_config"}


def _result(status: str, message: str, latency_s=None) -> Dict[str, Any]:
    return {"status": status, "message": message, "latency_s": latency_s}


def _classify_error(err: str) -> str:
    """Map a client ``"Error: ..."`` string to a health-check status."""
    e = (err or "").lower()
    if "timed out" in e or "timeout" in e:
        return "timeout"
    if "auth" in e or "api key" in e or "401" in e or "unauthorized" in e:
        return "auth_failed"
    if "not found" in e or "404" in e or "no such model" in e or "does not exist" in e:
        return "model_not_found"
    if ("could not connect" in e or "connection" in e or "refused" in e
            or "unreachable" in e or "502" in e or "503" in e):
        return "unreachable"
    return "error"


def health_check(provider: str, server: str = "", model: str = "",
                 api_key: Optional[str] = None, timeout: float = 120.0) -> Dict[str, Any]:
    """Probe a single model and return a status dict:

    ``{status, message, latency_s}`` where status is one of ``ok`` · ``no_verdict`` ·
    ``unreachable`` · ``auth_failed`` · ``model_not_found`` · ``timeout`` · ``error`` ·
    ``invalid_config``.
    """
    provider = (provider or "lmstudio").lower()
    if not model:
        return _result("invalid_config", "No model selected.")

    prompt = _HEALTH_PROMPT

    # Build the right client (max_tokens=None — let the server govern, like a real run).
    try:
        if provider == "anthropic":
            from forcastl.core.anthropic_client import AnthropicClient
            client = AnthropicClient(model_id=model, api_key=api_key,
                                     timeout=int(timeout), max_tokens=None)
        elif provider == "openai":
            from forcastl.core.openai_client import OpenAIClient
            client = OpenAIClient(model_id=model, api_key=api_key,
                                  timeout=int(timeout), max_tokens=None)
        else:  # lmstudio / OpenAI-compatible local server
            from forcastl.core.llm_client import LLMClient, check_lmstudio_model_state
            # Fast path: if LM Studio knows the model isn't present, fail before probing.
            if check_lmstudio_model_state(server, model) == "not-found":
                return _result("model_not_found",
                               f"Model '{model}' is not on the LM Studio server "
                               f"({server}). Check the id in LM Studio's My Models tab.")
            client = LLMClient(server_url=server, model_id=model,
                               timeout=int(timeout), max_tokens=None)
    except RuntimeError as e:
        # Missing API key, SDK not installed, etc.
        return _result("auth_failed", str(e))

    # Single probe. Clients return ("Error: ...", elapsed) rather than raising.
    start = time.time()
    try:
        text, elapsed = client.send_to_llm(prompt)
    except Exception as e:  # defensive — should not normally happen
        return _result(_classify_error(str(e)), str(e)[:300],
                       latency_s=round(time.time() - start, 1))

    latency = round(elapsed if isinstance(elapsed, (int, float)) else time.time() - start, 1)

    if isinstance(text, str) and text.startswith("Error:"):
        return _result(_classify_error(text), text[:300], latency_s=latency)

    incomplete, reason = is_incomplete_response(text)
    if incomplete:
        return _result(
            "no_verdict",
            "The model responded but did not return a MALICIOUS verdict "
            f"({reason}); its output may not follow the required format.",
            latency_s=latency)

    return _result(
        "ok",
        f"Model responded in {latency:.0f}s and returned a valid verdict.",
        latency_s=latency)
