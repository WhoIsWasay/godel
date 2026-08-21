import time

from domain import config


def call_with_retry(fn, attempts=None, backoff=None):
    """Invoke fn() with retry + exponential backoff.

    Retries all exceptions (rate-limit, connection resets, transient 5xx are the
    common cases). Fatal errors (auth, context-length) still fail, but they do so
    near-instantly so the retry cost is negligible.
    """
    attempts = attempts if attempts is not None else config.LLM_RETRY_ATTEMPTS
    backoff = backoff if backoff is not None else config.LLM_RETRY_BACKOFF

    last_exc = None
    for i in range(max(1, attempts)):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if i < attempts - 1:
                time.sleep(backoff ** i)
    raise last_exc
