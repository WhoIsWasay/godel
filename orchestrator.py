"""orchestrator.py — local quick-test entry point.

Thin wrapper over the real engine (domain.pipeline). Keeps the old
`python orchestrator.py` habit while always running the current pipeline.
Accepts an optional folder argument:

    python orchestrator.py                  # default: CollateralizeDebtPosition
    python orchestrator.py Benchmarks/foo   # explicit folder
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from domain.pipeline import run_pipeline

if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else "CollateralizeDebtPosition"
    run_pipeline(folder)
