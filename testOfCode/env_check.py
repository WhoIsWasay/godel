"""Shared test-environment flags.

Fixtures (sample .sol contracts) are deliberately NOT committed to the repo.
They live on the developer machine under testOfCode/fixtures/ (gitignored).
Tests that audit real contracts guard themselves with HAS_FIXTURES and skip
cleanly on CI / fresh clones, where only contract-free logic tests run."""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = os.path.join(ROOT, "testOfCode", "fixtures")


def _has_sol(d):
    return os.path.isdir(d) and any(f.endswith(".sol") for f in os.listdir(d))


HAS_FIXTURES = _has_sol(FIXTURES_DIR)
