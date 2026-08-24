# Gödel

**Enterprise-grade formal verification engine for smart contracts.**

Gödel bridges high-reasoning LLMs with deterministic SMT theorem proving (**Z3**) and native **Foundry EVM** sandbox fuzzing. Instead of spitting out noisy, pattern-matched false positives, Gödel translates natural language security intent and Solidity AST structures into rigorous mathematical proofs with a **0% False Positive rate** (evidence trail: [docs/BENCHMARKS.md](docs/BENCHMARKS.md)).

> *"New beginnings for software reliability."*

---

## 📊 Measured Results (planted-bug corpus)

7 seeded contracts, 23 planted vulnerabilities — audited end-to-end:

| Metric | Value |
|---|---|
| Bugs caught | **20 / 23 (87%)** |
| False positives reported | **0** |
| Largest contract | 461 LOC |

Full per-contract breakdown: [godel-site](https://whoiswasay.github.io/godel-site/) · artifacts under `output/` and `cache/fuzz/failures/`.

---

## 🏗️ Architecture Overview

Gödel abandons traditional single-threaded regex auditing in favor of a multi-agent, thread-safe graph architecture:

1. **Static Abstraction Layer (`abstracter.py`, deterministic):** Slither-based CFG extraction with pragma-aware solc resolution — no LLM involved.
2. **Semantic Encoder (`semantics.py`, deterministic):** Generates the Z3 harness (`build_model()`) directly from static-analysis facts. The LLM only writes the *property* against harness symbols — never the semantics. Untranslatable behavior is soundly havocked (over-approximation), never assumed.
3. **Inspector-Isolator Agent:** Deconstructs the contract and spawns isolated graph threads per execution function concurrently; 3x isolation passes with Jaccard + code-line-overlap deduplication before a Compositor merge.
4. **Z3 SMT Theorem Prover:** Algebraic search for counterexamples (`SAT`). Verdicts require explicit output sentinels — ambiguous scripts are `inconclusive`, never guessed.
5. **Thread-Safe Gatekeeper (`gatekeeper.py`):** Replays every candidate bug inside a local Foundry EVM sandbox using dynamic UUID test naming. Verdict classification reads structured `forge --json` reports first, text heuristics as fallback.
6. **CEGIS Self-Healing Loop:** Compiler errors during EVM validation are fed back to repair the test suite automatically.
7. **Fixer Agent:** Generates remediation patches, re-verified against the same invariant.

## 🔬 Model Fidelity & Soundness

Gödel's Z3 models encode uint256 as **unbounded integers** — a deliberate
*over*-approximation. The consequence is asymmetric, and we state it plainly:

- **UNSAT verdicts are sound proofs.** If no integer solution exists in the
  unbounded model, none exists in real uint256 either.
- **Overflow wraparound is not simulated.** Bugs that only manifest at the
  `2**256` boundary can be missed on the SAT side; they require an explicit
  BitVec follow-up pass (roadmap).
- Every harness carries a `model_quality` label (`FULL` / `PARTIAL`) and its
  verdicts are reported with that strength attached — aborts and inconclusive
  runs are never reported as "safe".

## 🛡️ Engineering Guarantees

- **Deterministic static stack (probed):** two independent abstraction runs produce byte-identical analysis dicts; harness encoding is byte-stable.
- **Script sandboxing:** LLM-generated Z3 property scripts pass an AST safety gate (imports, eval/exec/open, dunder escapes rejected before execution).
- **Honest verdict taxonomy:** UNSAT-safe vs over-approximated-safe vs inconclusive vs aborted are distinct terminal states in reporting.
- **LLM-free regression net:** 188 checks across routing, verdict labels, sentinel matrix, safety gate, gatekeeper classification (text+JSON), corpus smoke (`testOfCode/`, wired into CI via `.github/workflows/pipeline-tests.yml`).

## 🚀 Quickstart

```bash
pip install -r requirements.txt
python main.py --doctor                                   # environment readiness
python main.py --dry-run --contracts <folder>             # plumbing e2e, zero LLM calls
python main.py --invariant "total@new == bal[S]@new" --contracts <folder>   # deterministic invariant mode
python main.py --contracts <folder>                       # full audit
```

MCP integration for AI assistants: `python mcp_server.py` (see header of that file).

---

## 🛠️ What Changed in This Version (Changelog)

* **Concurrency & Thread Safety:** Upgraded `orchestrator.py` to handle 20+ parallel function graph threads simultaneously using dynamic file-naming locks in the gatekeeper sandbox.
* **CEGIS Auto-Healing Loop:** Added autonomous compiler-error feedback loops to heal failing Foundry test files across multi-iteration runs.
* **Red Herring Suppression:** Hardened Z3 path constraints to formally prove safety for bounded recursion, safe multi-variable unchecked math, and quantized rounding identities, eliminating alert fatigue.
* **Hardening pass (Aug 2026):** ElementTree-based XML extraction (fixes silent function-body truncation), AST safety gate for generated scripts, structured `forge --json` gatekeeper verdicts, worker-aware batch timeouts, absolute-path enforcement around the Slither chdir window, committed benchmark evidence ([docs/BENCHMARKS.md](docs/BENCHMARKS.md)).

---
Built By Wasay. August 2026.
