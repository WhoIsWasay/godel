"""Robust JSON extraction and truncation repair for LLM responses.

Every JSON parse site in the pipeline previously used ad-hoc
``split("```json")[1].split("```")[0]`` fence slicing plus a quote-count
repair. That combination fails in ways observed in production:

1. Backtick runs inside JSON string values (findings quote Solidity code,
   which itself can contain markdown fences) truncate the payload
   mid-object, so ``json.loads`` sees half a finding.
2. Truncation inside a key (``{"findings": [{"intent``) defeats the
   quote-count repair, so the whole pass's findings are silently replaced
   with an empty list — indistinguishable from "no bugs found".
3. Fence variants (uppercase `` ```JSON ``, unclosed fences, prose around
   the payload) cascade into ``json.loads('')`` errors.

This module centralizes one string-aware implementation used by all call
sites. Repair is deliberately CONTENT-PRESERVING only: it closes unclosed
strings/containers and may drop one dangling trailing member, but it never
silently discards whole chunks of payload — a degraded parse would
masquerade as a clean result. When content would have to be dropped, the
extraction fails so callers can flag/retry instead.
"""
import json
import logging
import re

logger = logging.getLogger(__name__)

# Fence opener with any language tag (```json, ```JSON, ```python, bare ```).
_FENCE_RE = re.compile(r"```[A-Za-z0-9_-]*[ \t]*\r?\n?(.*?)\r?```", re.DOTALL)
# A dangling trailing member like:  , "key":   (truncation right after a colon)
_TRAILING_MEMBER_RE = re.compile(r',\s*"(?:[^"\\]|\\.)*"\s*:\s*$')
# Upper bound on balanced-scan start positions (guards pathological inputs).
_MAX_BALANCED_TRIES = 32


def try_parse(text):
    """json.loads with strict=False (tolerates unescaped control chars).
    Returns the parsed value or None."""
    if not isinstance(text, str):
        return None
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text, strict=False)
    except (json.JSONDecodeError, ValueError):
        return None


def fenced_blocks(text: str) -> list:
    """Raw contents of every ```-fenced block in `text` (may be empty)."""
    if not isinstance(text, str):
        return []
    return _FENCE_RE.findall(text)


def _scan_state(fragment: str):
    """Single pass tracking container stack + in-string state."""
    stack = []
    in_str = False
    esc = False
    for ch in fragment:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch in "{[":
                stack.append("}" if ch == "{" else "]")
            elif ch in "}]":
                if stack and stack[-1] == ch:
                    stack.pop()
    return stack, in_str


def _terminate_open_string(fragment: str) -> str:
    """If the fragment ends inside an open JSON string, close it."""
    _, in_str = _scan_state(fragment)
    if not in_str:
        return fragment
    frag = fragment
    # A trailing lone escape would swallow the closing quote we append.
    if frag.endswith("\\") and not frag.endswith("\\\\"):
        frag = frag[:-1]
    return frag + '"'


def _close_containers(fragment: str) -> str:
    """Strip dangling trailing commas, then append the closers needed to
    balance every still-open container."""
    frag = fragment.rstrip()
    while frag.endswith(","):
        frag = frag[:-1].rstrip()
    stack, _ = _scan_state(frag)
    return frag + "".join(reversed(stack))


def _balanced_end(text: str, start: int):
    """Index just past the balanced container opening at text[start],
    or None if it never closes. String-aware: braces inside JSON strings
    do not affect the match."""
    stack = []
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch in "{[":
                stack.append("}" if ch == "{" else "]")
            elif ch in "}]":
                if not stack:
                    return None
                stack.pop()
                if not stack:
                    return i + 1
    return None


def repair_truncated_json(text: str):
    """Repair a JSON payload truncated mid-stream. Returns the parsed value
    or None when no content-preserving repair exists.

    Two repair shapes are attempted:
      1. close an unclosed trailing string and any open containers
         (covers the common max_tokens cutoff mid-value-string);
      2. additionally drop ONE dangling trailing member (`, "key":`)
         when truncation landed right after a colon.
    """
    if not isinstance(text, str):
        return None
    frag = text.strip()
    if not frag:
        return None

    direct = try_parse(frag)
    if direct is not None:
        return direct

    terminated = _terminate_open_string(frag)
    candidates = [_close_containers(terminated)]
    member_stripped = _TRAILING_MEMBER_RE.sub("", terminated)
    if member_stripped != terminated:
        candidates.append(_close_containers(member_stripped))

    for cand in candidates:
        value = try_parse(cand)
        if value is not None:
            return value
    return None


def extract_json_value(raw):
    """Extract the JSON value embedded in an LLM response.

    Returns (value, error): value is the parsed JSON (dict/list/scalar)
    and error is None on success; on failure value is None and error is a
    human-readable diagnostic.

    Candidate sources, in priority order:
      1. the whole text (already clean JSON);
      2. fenced code blocks, complete-parse first (correct fence extraction
         even when the JSON contains backtick sequences in strings is
         handled next by the balanced scan if the fence regex truncates);
      3. balanced brace/bracket spans anywhere in the text — string-aware,
         so backticks inside string values cannot corrupt the extraction;
      4. content after an unterminated trailing fence opener;
      5. content-preserving truncation repair of the whole text.
    """
    if raw is None:
        return None, "no content"
    text = str(raw).strip()
    if not text:
        return None, "no content"

    value = try_parse(text)
    if value is not None:
        return value, None

    blocks = fenced_blocks(text)
    for block in blocks:
        value = try_parse(block)
        if value is not None:
            return value, None

    # Repair a truncated TOP-LEVEL payload before the balanced-span scan:
    # otherwise a cutoff outer object lets the scan return a still-balanced
    # NESTED fragment (a degraded result) instead of closing the real one.
    value = repair_truncated_json(text)
    if value is not None:
        return value, None

    for opener in ("{", "["):
        idx = text.find(opener)
        tries = 0
        while idx != -1 and tries < _MAX_BALANCED_TRIES:
            end = _balanced_end(text, idx)
            if end is not None:
                value = try_parse(text[idx:end])
                if value is not None:
                    return value, None
            idx = text.find(opener, idx + 1)
            tries += 1

    for block in blocks:
        value = repair_truncated_json(block)
        if value is not None:
            return value, None

    last_fence = text.rfind("```")
    if last_fence != -1:
        tail = text[last_fence + 3:].strip()
        if tail:
            value = try_parse(tail) or repair_truncated_json(tail)
            if value is not None:
                return value, None

    return None, "no parseable JSON payload found in LLM response"
