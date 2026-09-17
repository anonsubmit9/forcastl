"""Cross-platform run durability for long evaluations.

Two OS-agnostic safeguards used by the detection CLI — and, transitively, by the
web UI, which launches the CLI as a subprocess:

* ``run_with_timeout`` — a hard wall-clock backstop around a single call. The
  network SDKs' own timeouts can fail to fire on a half-dead socket (e.g. after
  the host sleeps mid-request), wedging the whole run. This abandons the call and
  lets the loop continue, on any platform.
* ``keep_awake`` — best-effort prevention of idle sleep for the duration of a run
  (macOS ``caffeinate`` / Windows ``SetThreadExecutionState`` / Linux
  ``systemd-inhibit``). Never fails the run if unavailable.
"""
from __future__ import annotations

import contextlib
import os
import platform
import subprocess
import threading
from typing import Any, Callable


class CallTimeout(Exception):
    """A call did not return within its hard wall-clock budget."""


def run_with_timeout(fn: Callable[..., Any], timeout: float, *args, **kwargs) -> Any:
    """Run ``fn(*args, **kwargs)`` but give up after ``timeout`` seconds.

    The work runs in a daemon thread; if it overruns we abandon it (the orphaned
    thread dies with the process) and raise :class:`CallTimeout`. This is the
    backstop the SDK timeout failed to provide on a wedged socket — the run never
    freezes regardless of the connection state. ``timeout`` <= 0 means no limit.
    """
    if not timeout or timeout <= 0:
        return fn(*args, **kwargs)
    box: dict = {}

    def _worker():
        try:
            box["v"] = fn(*args, **kwargs)
        except BaseException as e:  # noqa: BLE001 - re-raised in the caller thread
            box["e"] = e

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise CallTimeout(f"call exceeded {timeout:.0f}s hard timeout")
    if "e" in box:
        raise box["e"]
    return box.get("v")


@contextlib.contextmanager
def keep_awake(reason: str = "forcastl evaluation"):
    """Best-effort: stop the host idle-sleeping while a run is in flight.

    Picks the right mechanism per OS; on anything unknown/unavailable it is a
    silent no-op so a missing tool can never break the evaluation.
    """
    system = platform.system()
    proc = None
    win = False
    try:
        if system == "Darwin":
            try:
                proc = subprocess.Popen(
                    ["caffeinate", "-i", "-w", str(os.getpid())],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:  # noqa: BLE001 - best effort
                proc = None
        elif system == "Windows":
            try:
                import ctypes
                # ES_CONTINUOUS (0x80000000) | ES_SYSTEM_REQUIRED (0x00000001)
                ctypes.windll.kernel32.SetThreadExecutionState(0x80000000 | 0x00000001)
                win = True
            except Exception:  # noqa: BLE001 - best effort
                win = False
        elif system == "Linux":
            try:
                proc = subprocess.Popen(
                    ["systemd-inhibit", "--what=idle:sleep", f"--why={reason}",
                     "sleep", "2147483647"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:  # noqa: BLE001 - best effort (e.g. no systemd)
                proc = None
        yield
    finally:
        try:
            if win:
                import ctypes
                ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)  # ES_CONTINUOUS clears
            elif proc is not None:
                proc.terminate()
        except Exception:  # noqa: BLE001 - best effort
            pass
