"""orchestrator.py — local quick-test entry point.

Thin wrapper over the real engine (domain.pipeline). Keeps the old
`python orchestrator.py` habit while always running the current pipeline.
Accepts an optional folder argument:

    python orchestrator.py                  # default: $GODEL_CONTRACTS_FOLDER
    python orchestrator.py Benchmarks/foo   # explicit folder
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from domain.pipeline import run_pipeline

if __name__ == "__main__":
    if len(sys.argv) > 1:
        folder = sys.argv[1]
        run_pipeline(folder)
    else:
        # Defer to config so env-var defaults apply; missing folder now fails
        # loudly inside run_pipeline instead of auditing nothing.
        run_pipeline()
