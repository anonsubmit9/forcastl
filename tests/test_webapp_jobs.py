"""Job-lifecycle coverage for the webapp: cap, eviction, cancel, clear, create.

These exercise the subprocess-managing paths in webapp/app.py without spawning
real processes — a fake Popen captures the command and a fake process drives
poll()/terminate(). Skipped when the web deps aren't installed.
"""
import pytest

try:
    from fastapi.testclient import TestClient
    import forcastl.webapp.app as webapp_app
    _WEB = True
    _ERR = None
except Exception as e:  # pragma: no cover
    _WEB = False
    _ERR = e

pytestmark = pytest.mark.skipif(not _WEB, reason=f"web deps not installed: {_ERR}")


class _FakeProc:
    """Stand-in for subprocess.Popen: poll() None=running / int=finished."""
    def __init__(self, running=True, returncode=0):
        self._running = running
        self.returncode = returncode
        self.terminated = False

    def poll(self):
        return None if self._running else self.returncode

    def terminate(self):
        self.terminated = True
        self._running = False


class _FakeLog:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _job(running=True, created_at="2026-01-01T00:00:00", kind="detect"):
    return {"kind": kind, "created_at": created_at, "cmd": ["x"],
            "log_path": "j.log", "process": _FakeProc(running=running),
            "log_file": _FakeLog()}


@pytest.fixture
def clean_jobs():
    """Isolate webapp_app.JOBS per test."""
    saved = dict(webapp_app.JOBS)
    webapp_app.JOBS.clear()
    try:
        yield webapp_app.JOBS
    finally:
        webapp_app.JOBS.clear()
        webapp_app.JOBS.update(saved)


# ── helper-level: cap + eviction ──────────────────────────────────────────────

def test_job_cap_raises_at_limit(clean_jobs):
    from fastapi import HTTPException
    for i in range(webapp_app.MAX_CONCURRENT_JOBS):
        clean_jobs[f"r{i}"] = _job(running=True)
    with pytest.raises(HTTPException) as ei:
        webapp_app._check_job_cap_locked()
    assert ei.value.status_code == 429


def test_job_cap_ignores_finished(clean_jobs):
    # Finished jobs don't count toward the running cap.
    for i in range(webapp_app.MAX_CONCURRENT_JOBS + 2):
        clean_jobs[f"d{i}"] = _job(running=False)
    webapp_app._check_job_cap_locked()  # must not raise


def test_eviction_drops_oldest_finished_and_closes_logs(clean_jobs):
    cap = webapp_app.MAX_FINISHED_JOBS
    logs = {}
    # cap + 3 finished jobs, ascending timestamps → 3 oldest should be evicted.
    for i in range(cap + 3):
        j = _job(running=False, created_at=f"2026-01-01T00:{i:02d}:00")
        logs[f"f{i}"] = j["log_file"]
        clean_jobs[f"f{i}"] = j
    webapp_app._evict_finished_jobs_locked()
    assert len(clean_jobs) == cap
    # The 3 oldest are gone and their log handles were closed.
    for i in range(3):
        assert f"f{i}" not in clean_jobs
        assert logs[f"f{i}"].closed is True


def test_eviction_keeps_running_jobs(clean_jobs):
    cap = webapp_app.MAX_FINISHED_JOBS
    clean_jobs["run"] = _job(running=True, created_at="2026-01-01T00:00:00")
    for i in range(cap + 2):
        clean_jobs[f"f{i}"] = _job(running=False, created_at=f"2026-01-01T01:{i:02d}:00")
    webapp_app._evict_finished_jobs_locked()
    assert "run" in clean_jobs  # a running job is never evicted


# ── endpoint-level: create / cancel / clear / get ─────────────────────────────

def test_run_detect_creates_job(clean_jobs, monkeypatch):
    captured = {}

    def fake_popen(cmd, **kw):
        captured["cmd"] = cmd
        return _FakeProc(running=True)

    monkeypatch.setattr(webapp_app.subprocess, "Popen", fake_popen)
    c = TestClient(webapp_app.app)
    r = c.post("/api/run/detect", json={"model": "m", "csv_dir": "data/csv"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "running"
    assert body["job_id"] in clean_jobs
    assert "forcastl.cli.detect" in captured["cmd"]


def test_run_detect_requires_csv_dir(clean_jobs, monkeypatch):
    monkeypatch.setattr(webapp_app.subprocess, "Popen",
                        lambda *a, **k: _FakeProc())
    c = TestClient(webapp_app.app)
    r = c.post("/api/run/detect", json={"model": "m"})  # no csv_dir
    assert r.status_code == 400


def test_run_detect_429_at_cap(clean_jobs, monkeypatch):
    for i in range(webapp_app.MAX_CONCURRENT_JOBS):
        clean_jobs[f"r{i}"] = _job(running=True)
    monkeypatch.setattr(webapp_app.subprocess, "Popen",
                        lambda *a, **k: _FakeProc())
    c = TestClient(webapp_app.app)
    r = c.post("/api/run/detect", json={"model": "m", "csv_dir": "data/csv"})
    assert r.status_code == 429


def test_cancel_running_job_terminates(clean_jobs):
    clean_jobs["j1"] = _job(running=True)
    proc = clean_jobs["j1"]["process"]
    c = TestClient(webapp_app.app)
    r = c.post("/api/jobs/j1/cancel")
    assert r.status_code == 200
    assert proc.terminated is True


def test_cancel_finished_job_409(clean_jobs):
    clean_jobs["j2"] = _job(running=False)
    c = TestClient(webapp_app.app)
    assert c.post("/api/jobs/j2/cancel").status_code == 409


def test_cancel_missing_job_404(clean_jobs):
    c = TestClient(webapp_app.app)
    assert c.post("/api/jobs/nope/cancel").status_code == 404


def test_clear_finished_removes_only_finished(clean_jobs):
    clean_jobs["run"] = _job(running=True)
    clean_jobs["done1"] = _job(running=False)
    clean_jobs["done2"] = _job(running=False)
    done_log = clean_jobs["done1"]["log_file"]
    c = TestClient(webapp_app.app)
    r = c.delete("/api/jobs/finished")
    assert r.status_code == 200
    assert r.json()["cleared"] == 2
    assert "run" in clean_jobs and "done1" not in clean_jobs
    assert done_log.closed is True


def test_list_and_get_job_status(clean_jobs):
    clean_jobs["j3"] = _job(running=True)
    c = TestClient(webapp_app.app)
    listing = c.get("/api/jobs").json()
    assert any(j["job_id"] == "j3" and j["status"] == "running" for j in listing)
    one = c.get("/api/jobs/j3").json()
    assert one["status"] == "running"
    assert c.get("/api/jobs/missing").status_code == 404


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
