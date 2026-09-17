"""Guard: the verdict thresholds hardcoded in ui.js must match config.VERDICT_THRESHOLDS.

The web UI re-implements driver tiering client-side (driverTier(metric, PASS, FAIL, ...))
so it can colour the KPI cards without a round-trip. Those numbers are duplicated from
the server-side source of truth; this test fails if the two drift apart.
"""
import re
from pathlib import Path

from forcastl import config

_UI_JS = Path(__file__).resolve().parents[1] / "src" / "forcastl" / "webapp" / "static" / "ui.js"


def _driver_bounds(metric_var: str):
    """Pull (pass, fail) from a `driverTier(<metric_var>, PASS, FAIL, ...)` call in ui.js."""
    src = _UI_JS.read_text(encoding="utf-8")
    m = re.search(
        rf"driverTier\(\s*{re.escape(metric_var)}\s*,\s*([\d.]+)\s*,\s*([\d.]+)",
        src,
    )
    assert m, f"driverTier call for {metric_var} not found in ui.js"
    return float(m.group(1)), float(m.group(2))


def test_recall_thresholds_match():
    p, f = _driver_bounds("recall")
    assert p == config.VERDICT_THRESHOLDS["recall"]["pass"]
    assert f == config.VERDICT_THRESHOLDS["recall"]["fail"]


def test_fp_rate_thresholds_match():
    p, f = _driver_bounds("fp")
    assert p == config.VERDICT_THRESHOLDS["fp_rate"]["pass"]
    assert f == config.VERDICT_THRESHOLDS["fp_rate"]["fail"]


def test_hallucination_thresholds_match():
    p, f = _driver_bounds("hallPct")
    assert p == config.VERDICT_THRESHOLDS["hallucination"]["pass"]
    assert f == config.VERDICT_THRESHOLDS["hallucination"]["fail"]
