"""Offline concurrency/race regression tests — zero API calls, zero credits.

Locks in the three hardening fixes from the CI run 33307904841 post-mortem:
  1. guarded_invoke is the single LLM choke point and actually caps
     concurrent provider calls (the old inspector-only semaphore left the
     other six call sites unthrottled).
  2. _drain_late_futures collects late-but-alive graphs and swaps their
     real results in for timeout placeholders — but is capped so a wedged
     thread cannot hang the pipeline forever.
  3. _unlink_quietly never lets a locked temp file turn a verdict into a
     raw PermissionError (Windows timeout-kill race).
"""

import sys
import threading
import time
import concurrent.futures
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ------------------------------------------------ 1. LLM concurrency throttle

class _FakeAgent:
    """Records peak concurrent invocations."""

    def __init__(self):
        self._lock = threading.Lock()
        self._active = 0
        self.peak = 0

    def invoke(self, messages):
        with self._lock:
            self._active += 1
            self.peak = max(self.peak, self._active)
        time.sleep(0.05)
        with self._lock:
            self._active -= 1
        class _R:
            content = "ok"
        return _R()


def test_guarded_invoke_caps_concurrency():
    import domain.llm_utils as lu
    original = lu._LLM_SEMAPHORE
    try:
        lu._LLM_SEMAPHORE = threading.Semaphore(2)
        agent = _FakeAgent()
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            list(ex.map(lambda _: lu.guarded_invoke(agent, ["m"]), range(12)))
        assert agent.peak <= 2, f"semaphore bypassed: peak={agent.peak}"
        assert agent.peak >= 1
    finally:
        lu._LLM_SEMAPHORE = original


def test_guarded_invoke_is_the_single_chokepoint():
    """Every retried LLM call must route through guarded_invoke — a direct
    agent.invoke inside call_with_retry recreates the unthrottled burst bug.
    Two checks: any module using call_with_retry must also import the guard,
    and no simple direct-invoke lambda may remain."""
    import re
    for path in (PROJECT_ROOT / "domain").glob("*.py"):
        if path.name == "llm_utils.py":
            continue
        text = path.read_text(encoding="utf-8")
        if "call_with_retry(" not in text:
            continue
        assert "guarded_invoke" in text, \
            f"{path.name}: uses call_with_retry without guarded_invoke"
        direct = re.search(r"call_with_retry\(\s*lambda:\s*[\w.]+\.invoke\(", text)
        assert not direct, f"{path.name}: direct agent.invoke inside call_with_retry"


# ------------------------------------------------ 2. late-future drain

def _make_future(delay, result):
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    fut = ex.submit(lambda: (time.sleep(delay), result)[1])
    ex.shutdown(wait=False)
    return fut


def test_drain_collects_late_result_and_replaces_placeholder(monkeypatch):
    from domain import pipeline

    collected = {}

    def fake_collect(future, func_name, stem, results):
        collected[func_name] = future.result()
        results.append({"contract": stem, "function": func_name,
                        "qc_status": "confirmed"})

    monkeypatch.setattr(pipeline, "_collect_future_result", fake_collect)
    monkeypatch.setattr(pipeline.config, "PER_FUNCTION_TIMEOUT", 10.0)

    fut = _make_future(0.05, {"state": "done"})
    future_to_func = {fut: "repay"}
    results = [{"contract": "C", "function": "repay", "qc_status": "timeout"}]
    pipeline._drain_late_futures(future_to_func, set(), "C", results)

    assert collected["repay"] == {"state": "done"}
    assert all(r["qc_status"] != "timeout" for r in results), \
        "timeout placeholder must be superseded by the real late result"
    assert any(r["qc_status"] == "confirmed" for r in results)


def test_drain_cap_abandons_wedged_thread(monkeypatch):
    """A thread that never finishes inside the cap must NOT hang the pipeline;
    its placeholder stands."""
    from domain import pipeline

    def fake_collect(future, func_name, stem, results):
        results.append({"contract": stem, "function": func_name,
                        "qc_status": "confirmed"})

    monkeypatch.setattr(pipeline, "_collect_future_result", fake_collect)
    monkeypatch.setattr(pipeline.config, "PER_FUNCTION_TIMEOUT", 0.3)

    fut = _make_future(1.5, None)  # finishes long after the cap
    future_to_func = {fut: "borrow"}
    results = [{"contract": "C", "function": "borrow", "qc_status": "timeout"}]
    t0 = time.time()
    pipeline._drain_late_futures(future_to_func, set(), "C", results)
    elapsed = time.time() - t0

    assert elapsed < 1.2, f"drain blocked {elapsed:.1f}s — cap not enforced"
    assert results == [{"contract": "C", "function": "borrow",
                        "qc_status": "timeout"}], "placeholder must stand"
    fut.result(timeout=5)  # let the background thread finish cleanly


def test_drain_exception_keeps_placeholder_and_records_error(monkeypatch):
    from domain import pipeline

    def bad_collect(future, func_name, stem, results):
        raise RuntimeError("graph exploded")

    monkeypatch.setattr(pipeline, "_collect_future_result", bad_collect)
    monkeypatch.setattr(pipeline.config, "PER_FUNCTION_TIMEOUT", 10.0)

    fut = _make_future(0.05, None)
    results = [{"contract": "C", "function": "deposit", "qc_status": "timeout"}]
    pipeline._drain_late_futures({fut: "deposit"}, set(), "C", results)

    statuses = [r["qc_status"] for r in results]
    assert "timeout" in statuses, "placeholder removed despite collection error"
    assert "graph_error" in statuses, \
        "the graph exception must surface as an error artifact"


# ------------------------------------------------ 3. temp-file unlink race

def test_unlink_quietly_removes_file():
    import tempfile
    from domain.z3_runner import _unlink_quietly
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name
    _unlink_quietly(path)
    assert not Path(path).exists()


def test_unlink_quietly_swallows_missing_file():
    from domain.z3_runner import _unlink_quietly
    _unlink_quietly(str(PROJECT_ROOT / "no_such_temp_file_xyz.py"))  # must not raise
