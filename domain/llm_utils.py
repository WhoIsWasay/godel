import random
import time

from domain import config

# HTTP status codes that retrying can never fix (auth, bad request, billing,
# context length). Everything else (429, 5xx, timeouts, connection resets)
# is considered transient.
NON_RETRYABLE_STATUS = {400, 401, 403, 404, 422}

# Substring fallbacks for exceptions that carry no .status_code attribute.
_NON_RETRYABLE_TEXT = (
    "invalid api key", "authentication", "incorrect api key", "unauthorized",
    "context length", "maximum context", "billing", "quota exceeded",
    "insufficient", "model_not_found", "permission denied",
)


class EmptyResponseError(Exception):
    """Provider returned HTTP success but empty content.

    Observed as a transient DeepSeek episode where every concurrent call got
    an instant 200 with no content. No status_code and no non-retryable text
    marker, so call_with_retry treats it as transient and retries.
    """


def _status_code(exc: Exception):
    return getattr(exc, "status_code", None)


def _retry_after(exc: Exception) -> float | None:
    """Extract Retry-After (seconds) from an exception's response headers."""
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None) or {}
    value = headers.get("retry-after") or headers.get("Retry-After")
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return None


def is_non_retryable(exc: Exception) -> bool:
    status = _status_code(exc)
    if status is not None:
        return status in NON_RETRYABLE_STATUS
    text = str(exc).lower()
    return any(marker in text for marker in _NON_RETRYABLE_TEXT)


def _default_sleep(seconds: float):
    time.sleep(seconds)


def call_with_retry(fn, attempts=None, backoff=None, sleep_fn=_default_sleep):
    """Invoke fn() with retry + exponential backoff + jitter.

    - Non-retryable errors (auth/billing/context-length) fail immediately.
    - Rate limits honour Retry-After when the API provides it.
    - Backoff includes uniform jitter to avoid thundering-herd retries.
    """
    attempts = attempts if attempts is not None else config.LLM_RETRY_ATTEMPTS
    backoff = backoff if backoff is not None else config.LLM_RETRY_BACKOFF
    attempts = max(1, attempts)

    last_exc = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if i >= attempts - 1 or is_non_retryable(exc):
                raise
            retry_after = _retry_after(exc)
            if retry_after is not None:
                delay = retry_after
            else:
                # exponential backoff with up to 50% jitter
                delay = (backoff ** i) * (1.0 + random.uniform(0.0, 0.5))
            sleep_fn(delay)
    raise last_exc
