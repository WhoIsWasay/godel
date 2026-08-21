import os
import sys
import argparse

sys.stdout.reconfigure(encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description="Gödel multi-agent Solidity audit pipeline")
    parser.add_argument("--contracts", default=None, help="Path to the folder of .sol files to audit")
    parser.add_argument("--dry-run", action="store_true", help="Validate plumbing without calling LLMs")
    parser.add_argument("--timeout", type=float, default=None, help="Per-function timeout in seconds")
    args = parser.parse_args()

    # Set env vars BEFORE importing the pipeline so domain.config picks them up.
    if args.dry_run:
        os.environ["GODEL_DRY_RUN"] = "1"
    if args.timeout is not None:
        os.environ["GODEL_PER_FUNCTION_TIMEOUT"] = str(args.timeout)

    from domain.config import CONTRACTS_FOLDER
    from domain.pipeline import run_pipeline

    folder = args.contracts or CONTRACTS_FOLDER
    results = run_pipeline(folder)

    print(f"\n=== SUMMARY: {len(results)} verified finding(s) ===")
    for r in results:
        print(f"  [{r.get('severity', 'unknown').upper()}] {r.get('contract')}::{r.get('function')} ({r.get('qc_status', 'unknown')})")

    return results


if __name__ == "__main__":
    main()
