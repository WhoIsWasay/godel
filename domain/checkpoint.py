"""Checkpoint/resume for the Gödel pipeline.

Two complementary mechanisms:

1. `build_memory_saver()` — a LangGraph-native in-memory checkpointer.
   Survives graph-level failures within a single process (an exception in
   a downstream node can be retried without re-running earlier phases).
   Lost on process exit.

2. `FileCheckpointer` — writes a JSON snapshot of the graph state after
   every node. Survives hard crashes (OOM, SIGKILL, API-key revoked).
   Recovery: `recover_state(dir)` (or `load_latest()` + `_deserialize_state`)
   feeding the state into a freshly built graph.

State serialization is defensive: non-JSON-serializable fields are dropped
with a warning rather than failing the whole checkpoint. LangChain BaseMessage
objects round-trip via `messages_to_dict` / `messages_from_dict`.
"""
import glob
import json
import logging
import os
import threading
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _serialize_state(state: dict) -> dict:
    """JSON-safe conversion of a GraphState dict.

    BaseMessage sequences are converted via langchain's messages_to_dict so
    they round-trip through messages_from_dict. Any field that refuses to
    serialize is dropped with a warning — a partial checkpoint is strictly
    better than none, and the dropped field will be recomputed on resume.
    """
    out = {}
    for k, v in state.items():
        if k == "messages" and isinstance(v, (list, tuple)):
            try:
                from langchain_core.messages import messages_to_dict
                out[k] = {"__messages__": messages_to_dict(list(v))}
                continue
            except Exception as e:
                logger.warning("checkpoint: failed to serialize messages (%s); dropping", e)
                continue
        try:
            json.dumps(v)
            out[k] = v
        except (TypeError, ValueError):
            logger.warning("checkpoint: dropping non-serializable field %r", k)
    return out


def _deserialize_state(raw: dict) -> dict:
    """Inverse of `_serialize_state`. Messages are restored via
    messages_from_dict; other fields are passed through verbatim."""
    out = dict(raw)
    if "messages" in out and isinstance(out["messages"], dict) \
            and "__messages__" in out["messages"]:
        try:
            from langchain_core.messages import messages_from_dict
            out["messages"] = messages_from_dict(out["messages"]["__messages__"])
        except Exception as e:
            logger.warning("checkpoint: failed to deserialize messages (%s); resetting", e)
            out["messages"] = []
    return out


class FileCheckpointer:
    """File-backed checkpoint writer. One JSON file per snapshot.

    Writes are atomic (temp file + fsync + os.replace), so a crash
    mid-write can never leave a half-written checkpoint behind. The most
    recent checkpoint is tagged via `latest.json` (a full copy, not a
    symlink, to stay portable across filesystems). If `latest.json` is
    missing or corrupt, `load_latest()` falls back to the newest
    parseable `ckpt_*.json` in the directory."""

    def __init__(self, checkpoint_dir: str):
        self.dir = checkpoint_dir
        os.makedirs(self.dir, exist_ok=True)

    @staticmethod
    def _atomic_write_json(path: str, payload: dict) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def save(self, state: dict, *, node_name: str, step: int) -> str:
        """Persist `state` and return the checkpoint path."""
        payload = {
            "step": step,
            "node": node_name,
            "next_agent": state.get("next_agent", ""),
            "state": _serialize_state(state),
        }
        path = os.path.join(self.dir, f"ckpt_{step:05d}_{node_name}.json")
        self._atomic_write_json(path, payload)
        self._atomic_write_json(os.path.join(self.dir, "latest.json"), payload)
        return path

    def load_latest(self) -> Optional[dict]:
        """Return the most recent payload dict, or None if nothing saved.

        Corrupt `latest.json` (crash between the two writes, disk full,
        manual edit) never raises — we scan the numbered checkpoints in
        reverse order and return the first one that parses."""
        latest = os.path.join(self.dir, "latest.json")
        if os.path.exists(latest):
            try:
                with open(latest, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("checkpoint: latest.json unreadable (%s); "
                               "scanning numbered checkpoints", e)
        # Reverse sort of ckpt_NNNNN_*.json == newest first (fixed-width step).
        candidates = sorted(glob.glob(os.path.join(self.dir, "ckpt_*.json")),
                            reverse=True)
        for cand in candidates:
            try:
                with open(cand, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
        return None


def recover_state(checkpoint_dir: str) -> Optional[dict]:
    """Convenience wrapper: returns the deserialized state dict from the
    latest checkpoint, or None if no checkpoint exists."""
    ckpt = FileCheckpointer(checkpoint_dir).load_latest()
    if ckpt is None:
        return None
    return _deserialize_state(ckpt["state"])


def build_memory_saver():
    """Return a fresh LangGraph MemorySaver (in-process checkpointer)."""
    from langgraph.checkpoint.memory import MemorySaver
    return MemorySaver()


def wrap_nodes_with_file_checkpointer(node_fns: dict, checkpointer: FileCheckpointer):
    """Return {name: wrapped_fn} that saves state after each node runs.

    The wrapper captures the step counter in a closure so successive node
    invocations get monotonically increasing step numbers. This is the
    wiring used inside `build_godel_graph(checkpoint_dir=...)`.
    """
    counter = {"n": 0}
    lock = threading.Lock()
    wrapped = {}
    for name, fn in node_fns.items():
        def _make(_name, _fn):
            def _wrapped(state):
                result = _fn(state)
                merged = {**state, **(result or {})}
                # The messages channel uses an append reducer: a node's
                # return value carries only the NEW messages, so the
                # snapshot must append them instead of overwriting history.
                prior = state.get("messages") or []
                added = (result or {}).get("messages") or []
                if isinstance(added, list):
                    merged["messages"] = list(prior) + added
                try:
                    with lock:
                        step = counter["n"]
                        counter["n"] += 1
                    checkpointer.save(merged, node_name=_name, step=step)
                except Exception as e:
                    logger.warning("checkpoint save failed for %s (non-fatal): %s", _name, e)
                return result
            _wrapped.__name__ = f"ckpt_{_name}"
            return _wrapped
        wrapped[name] = _make(name, fn)
    return wrapped
