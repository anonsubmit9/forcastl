#!/usr/bin/env python3
"""
LLM Model Selector Script

This script allows users to connect to an LLM server by providing IP and port,
fetch available models, and select one for testing.
"""

import threading
import time
import requests
import sys
import re
from typing import List, Dict, Optional, Tuple


class LLMModelSelector:
    def __init__(self):
        self.server_url = None
        self.selected_model = None
        self.available_models = []

    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ip_pattern, ip)) or ip.lower() == 'localhost'

    def validate_port(self, port: str) -> bool:
        """Validate port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False

    def get_user_input(self) -> Tuple[str, str]:
        """Get IP and port from user input"""
        print("LLM Model Selector")
        print("=" * 20)
        
        while True:
            ip = input("Enter LLM server IP address (or 'localhost'): ").strip()
            if not ip:
                print("[ERROR] IP address cannot be empty. Please try again.")
                continue
            
            if not self.validate_ip(ip):
                print("[ERROR] Invalid IP address format. Please enter a valid IP address.")
                continue
            break

        while True:
            port = input("Enter port number: ").strip()
            if not port:
                print("[ERROR] Port cannot be empty. Please try again.")
                continue
            
            if not self.validate_port(port):
                print("[ERROR] Invalid port number. Please enter a number between 1-65535.")
                continue
            break

        return ip, port

    def build_server_url(self, ip: str, port: str) -> str:
        """Build server URL from IP and port"""
        if ip.lower() == 'localhost':
            return f"http://localhost:{port}"
        return f"http://{ip}:{port}"

    def fetch_models_openai_format(self) -> Optional[List[Dict]]:
        """Fetch models using OpenAI-compatible API format"""
        try:
            response = requests.get(f"{self.server_url}/v1/models", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    return data['data']
        except Exception:
            pass
        return None

    def fetch_models_ollama_format(self) -> Optional[List[Dict]]:
        """Fetch models using Ollama API format"""
        try:
            response = requests.get(f"{self.server_url}/api/tags", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'models' in data:
                    return [{'id': model['name'], 'name': model['name']} for model in data['models']]
        except Exception:
            pass
        return None

    def fetch_models_custom_format(self) -> Optional[List[Dict]]:
        """Try custom endpoints for model listing"""
        endpoints = ['/models', '/api/models', '/list']
        
        for endpoint in endpoints:
            try:
                response = requests.get(f"{self.server_url}{endpoint}", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, list):
                        return [{'id': model, 'name': model} if isinstance(model, str) else model for model in data]
                    elif isinstance(data, dict) and 'models' in data:
                        return data['models']
            except Exception:
                continue
        return None


    def _is_valid_llm(self, model: Dict) -> bool:
        """Filter models by name patterns only (fast, no API calls)"""
        model_name = model.get('name', model.get('id', ''))

        # Filter out obvious embedding models
        embedding_keywords = ['embedding', 'embed', 'vector', 'retrieval']
        if any(keyword in model_name.lower() for keyword in embedding_keywords):
            return False

        return True

    def fetch_available_models(self) -> bool:
        """Fetch available models from the server and filter for LLM capability"""
        print(f"\nConnecting to {self.server_url}...")

        model_formats = [
            ("OpenAI-compatible", self.fetch_models_openai_format),
            ("Ollama", self.fetch_models_ollama_format),
            ("Custom endpoints", self.fetch_models_custom_format)
        ]

        for format_name, fetch_func in model_formats:
            print(f"   Trying {format_name} format...")
            models = fetch_func()
            if models:
                print(f"[OK] Successfully connected using {format_name} format!")
                print(f"   Found {len(models)} models, filtering for LLM capability...")

                # Filter models for LLM capability (fast name-based filtering)
                llm_models = []
                for model in models:
                    if self._is_valid_llm(model):
                        llm_models.append(model)
                    else:
                        model_name = model.get('name', model.get('id', 'Unknown'))
                        print(f"   [SKIP] Filtered out: {model_name} (embedding/non-LLM model)")

                if llm_models:
                    # Simple alphabetical sort
                    llm_models.sort(key=lambda m: m.get('name', m.get('id', '')).lower())

                    self.available_models = llm_models
                    print(f"   Found {len(llm_models)} compatible LLM models.")
                    return True
                else:
                    print("[ERROR] No compatible LLM models found after filtering.")
                    continue

        print("[ERROR] Failed to fetch models. Server may be down or using an unsupported API format.")
        return False

    def display_models(self) -> None:
        """Display available models"""
        print(f"\nAvailable Models ({len(self.available_models)}):")
        print("-" * 50)

        for i, model in enumerate(self.available_models, 1):
            model_name = model.get('name', model.get('id', 'Unknown'))
            print(f"{i:2d}. {model_name}")

    def select_model(self) -> bool:
        """Allow user to select a model"""
        if not self.available_models:
            print("[ERROR] No models available for selection.")
            return False

        self.display_models()
        
        while True:
            try:
                choice = input(f"\nSelect a model (1-{len(self.available_models)}) or 'q' to quit: ").strip().lower()
                
                if choice == 'q':
                    print("Goodbye!")
                    return False
                
                choice_num = int(choice)
                if 1 <= choice_num <= len(self.available_models):
                    self.selected_model = self.available_models[choice_num - 1]
                    model_name = self.selected_model.get('name', self.selected_model.get('id', 'Unknown'))
                    print(f"[OK] Selected model: {model_name}")
                    return True
                else:
                    print(f"[ERROR] Please enter a number between 1 and {len(self.available_models)}")
                    
            except ValueError:
                print("[ERROR] Please enter a valid number or 'q' to quit")

    def show_selection_summary(self) -> None:
        """Show summary of current selection"""
        if self.selected_model and self.server_url:
            model_name = self.selected_model.get('name', self.selected_model.get('id', 'Unknown'))
            print("\nCurrent Configuration:")
            print(f"   Server: {self.server_url}")
            print(f"   Model:  {model_name}")
            print("\n[OK] Ready for testing!")

    def run(self) -> None:
        """Main execution loop"""
        try:
            while True:
                ip, port = self.get_user_input()
                self.server_url = self.build_server_url(ip, port)
                
                if self.fetch_available_models():
                    if self.select_model():
                        self.show_selection_summary()
                        break
                else:
                    retry = input("\nWould you like to try a different server? (y/n): ").strip().lower()
                    if retry != 'y':
                        print("Goodbye!")
                        break
                        
        except KeyboardInterrupt:
            print("\n\nInterrupted by user. Goodbye!")
        except Exception as e:
            print(f"\n[ERROR] An unexpected error occurred: {e}")
            sys.exit(1)


def main():
    """Main function"""
    selector = LLMModelSelector()
    selector.run()


if __name__ == "__main__":
    main()


def _parse_lmstudio_v1_models(payload: dict, model_id: str) -> Optional[str]:
    """Parse /api/v1/models response: {'models': [{'key', 'loaded_instances', ...}]}."""
    entries = payload.get('models')
    if not isinstance(entries, list) or not entries:
        return None
    if not all(isinstance(e, dict) and 'key' in e and 'loaded_instances' in e for e in entries):
        return None
    for entry in entries:
        if entry.get('key') == model_id:
            return "loaded" if entry.get('loaded_instances') else "not-loaded"
    return "not-found"


def _parse_lmstudio_v0_models(payload: dict, model_id: str) -> Optional[str]:
    """Parse /api/v0/models response: {'data': [{'id', 'state', ...}]}."""
    entries = payload.get('data')
    if not isinstance(entries, list) or not entries:
        return None
    if not all(isinstance(e, dict) and 'id' in e and 'state' in e for e in entries):
        return None
    for entry in entries:
        if entry.get('id') == model_id:
            return entry.get('state') or 'unknown'
    return "not-found"


def check_lmstudio_model_state(server_url: str, model_id: str,
                               timeout: float = 5.0) -> Optional[str]:
    """Query LM Studio's native REST API for a model's load state.

    Tries /api/v1/models first, falls back to /api/v0/models for older builds.
    Returns:
      "loaded" / "not-loaded" / other state string if the model entry exists,
      "not-found" if LM Studio returned its list but the id is absent,
      None if the server is not LM Studio (endpoint missing or shape mismatch).
    """
    probes = (
        ("/api/v1/models", _parse_lmstudio_v1_models),
        ("/api/v0/models", _parse_lmstudio_v0_models),
    )
    for path, parser in probes:
        try:
            resp = requests.get(f"{server_url}{path}", timeout=timeout)
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        try:
            payload = resp.json()
        except ValueError:
            continue
        if not isinstance(payload, dict):
            continue
        result = parser(payload, model_id)
        if result is not None:
            return result
    return None


def attempt_lmstudio_load(server_url: str, model_id: str,
                          timeout: float = 180.0) -> Tuple[bool, Optional[str]]:
    """Ask LM Studio to load the named model via /api/v1/models/load.

    Returns ``(success, error_message)``. On a missing endpoint (older
    LM Studio builds) success is False and the caller should fall back to
    asking the user to load the model manually. Loading a large quantized
    model can take 30-90 s; the default timeout accommodates that.
    """
    try:
        resp = requests.post(
            f"{server_url}/api/v1/models/load",
            json={"model": model_id},
            timeout=timeout,
        )
    except requests.RequestException as e:
        return False, str(e)

    if resp.status_code in (200, 201, 202, 204):
        return True, None
    # 404 / 405 / 501 etc. — endpoint not supported on this LM Studio version
    if resp.status_code in (404, 405, 501):
        return False, f"LM Studio /api/v1/models/load not supported (HTTP {resp.status_code})"
    # Surface the body when present so the user sees the upstream reason.
    detail = ""
    try:
        body = resp.json()
        if isinstance(body, dict):
            detail = body.get("error", {}).get("message") or body.get("message") or ""
    except ValueError:
        detail = (resp.text or "")[:200]
    return False, f"HTTP {resp.status_code}" + (f": {detail}" if detail else "")


class LLMClient:
    """Handles HTTP communication with an OpenAI-compatible LLM server."""

    def __init__(self, server_url: str, model_id: str, timeout: int = 120,
                 max_tokens: Optional[int] = None):
        self.server_url = server_url
        self.model_id = model_id
        self.timeout = timeout
        # None => do not impose an output-token cap; the model server (LM Studio,
        # etc.) owns that. We just send the prompt and document the response.
        self.max_tokens = max_tokens
        self._preflight_done = False

    def _preflight_check(self) -> Optional[str]:
        """One-shot check: verify the target model is loaded on LM Studio,
        and auto-load it via /api/v1/models/load when it isn't.

        Returns an error string to propagate back, or None if OK / not LM Studio.
        """
        if self._preflight_done:
            return None
        self._preflight_done = True
        state = check_lmstudio_model_state(self.server_url, self.model_id)
        if state is None or state == "loaded":
            return None
        if state == "not-found":
            return (f"Error: Model '{self.model_id}' not found on LM Studio server. "
                    f"Check the model id in LM Studio's My Models tab.")

        # State is "not-loaded" (or some other non-loaded status). Try to
        # trigger the load ourselves so the user doesn't have to alt-tab.
        # Big quantized models take ~30-90 s; cap at 3 min.
        print(f"[INFO] Model '{self.model_id}' not loaded on LM Studio - "
              f"requesting load... (this can take a minute)", flush=True)
        loaded_ok, load_err = attempt_lmstudio_load(self.server_url, self.model_id,
                                                   timeout=180.0)
        if loaded_ok:
            # Re-confirm the state actually changed (the load endpoint can
            # return success while the instance is still warming up).
            new_state = check_lmstudio_model_state(self.server_url, self.model_id)
            if new_state == "loaded":
                print(f"[OK] Model '{self.model_id}' loaded.", flush=True)
                return None
            # POST returned 2xx but the model still isn't reporting loaded —
            # surface a clear error rather than letting the user wait further.
            return (f"Error: LM Studio accepted the load request for "
                    f"'{self.model_id}' but the model still reports "
                    f"state '{new_state}'. Try loading it manually.")
        # Auto-load failed — fall back to the original error message so the
        # user knows to load manually.
        return (f"Error: Model '{self.model_id}' is not loaded on LM Studio "
                f"(state: {state}); auto-load failed: {load_err}. "
                f"Load it in the LM Studio app before running.")

    def _total_budget(self, prompt: str) -> float:
        """Wall-clock deadline for a single ``send_to_llm`` call (incl. retries).

        ``--timeout`` is a **hard cap** — there is no silent per-prompt
        extension, so the configured number means what it says. Files that
        legitimately need longer generation should raise ``--timeout``
        explicitly.
        """
        return float(self.timeout)

    def send_to_llm(self, prompt: str, *, temperature: float = 0.0) -> tuple:
        """Send prompt to the LLM and return ``(response_text, response_time)``.

        Enforces a **hard wall-clock deadline** (``--timeout``) on the whole call
        including retries. ``requests``'s own ``timeout`` only caps the gap
        between bytes, and closing a ``Session`` does not reliably interrupt a
        request already blocked in ``recv()`` on another thread — so a server
        that trickles a long (non-streaming) response can run far past the limit.
        We therefore run each attempt on a *daemon* worker and ``join(remaining)``:
        when the deadline passes we abandon the in-flight request (the daemon
        does not block process exit; its own read-timeout reaps it sooner) and
        return a clean timeout, so the run always moves on.
        """
        start_time = time.time()
        preflight_error = self._preflight_check()
        if preflight_error:
            return preflight_error, time.time() - start_time

        deadline = start_time + self._total_budget(prompt)
        max_attempts = 3
        backoff_seconds = [0.0, 1.0, 2.5]
        last_error = None

        # Minimum budget per attempt: below this, skip rather than waste time.
        # Must be small enough that a caller-specified `timeout=1` still fires once.
        MIN_ATTEMPT_BUDGET = 0.1
        payload = {
            "model": self.model_id,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        # Only cap the output when a cap was explicitly requested; otherwise let
        # the server use its own configured limit.
        if self.max_tokens is not None:
            payload["max_tokens"] = self.max_tokens

        for attempt in range(max_attempts):
            remaining = deadline - time.time()
            if remaining <= MIN_ATTEMPT_BUDGET:
                last_error = f"Request timed out after {self.timeout}s"
                break

            if attempt > 0:
                sleep_for = min(backoff_seconds[min(attempt, len(backoff_seconds) - 1)],
                                max(0.0, remaining - MIN_ATTEMPT_BUDGET))
                if sleep_for > 0:
                    time.sleep(sleep_for)
                remaining = deadline - time.time()
                if remaining <= MIN_ATTEMPT_BUDGET:
                    last_error = f"Request timed out after {self.timeout}s"
                    break

            session = requests.Session()
            box = {}

            def _do_post():
                try:
                    box["resp"] = session.post(
                        f"{self.server_url}/v1/chat/completions",
                        json=payload,
                        timeout=remaining,
                    )
                except Exception as exc:  # surfaced + classified in the caller thread
                    box["exc"] = exc

            worker = threading.Thread(target=_do_post, daemon=True)
            worker.start()
            worker.join(remaining)

            try:
                if worker.is_alive():
                    # Hard wall-clock deadline hit — abandon the in-flight request.
                    last_error = f"Request timed out after {self.timeout}s"
                    break

                exc = box.get("exc")
                if exc is not None:
                    if isinstance(exc, (requests.Timeout, requests.ConnectionError,
                                        requests.RequestException)):
                        if time.time() >= deadline:
                            last_error = f"Request timed out after {self.timeout}s"
                            break
                        last_error = str(exc)
                        continue
                    return f"Error: {exc}", time.time() - start_time

                response = box["resp"]
                if response.status_code == 200:
                    try:
                        data = response.json()
                        llm_response = data['choices'][0]['message']['content']
                    except (KeyError, IndexError, TypeError, ValueError) as e:
                        return f"Error: Malformed API response - {e}", time.time() - start_time
                    return llm_response, time.time() - start_time

                if response.status_code in (429, 500, 502, 503, 504):
                    last_error = f"HTTP {response.status_code}"
                    continue
                return f"Error: HTTP {response.status_code}", time.time() - start_time
            finally:
                try:
                    session.close()
                except Exception:
                    pass

        return f"Error: {last_error or 'LLM request failed'}", time.time() - start_time