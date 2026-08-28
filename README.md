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

Gödel's Z3 models encode uint256 as **bounded integers [0, 2^256-1]** — a
deliberate *over*-approximation (intermediate arithmetic is unbounded). The
consequence is asymmetric, and we state it plainly:

- **UNSAT verdicts are sound proofs.** If no integer solution exists in the
  bounded model, none exists in real uint256 either.
- **Overflow is detected.** Individual variables are capped at `2**256 - 1`, so
  Z3 can find counterexamples where arithmetic results exceed the uint256
  maximum. Modular wraparound is still NOT simulated — use `--wrap-probe`
  (BitVec-256) for exact wrap semantics.
- **Vacuity is checked.** Every UNSAT verdict triggers a reachability probe that
  verifies the function's pre-state is satisfiable. Vacuous results (where
  guards contradict bounds) are labeled `NOT a real proof` in reporting.
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

* **Performance pass (Aug 2026):** Cut per-function wall time ~10-15x on finding-free paths and ~2-5x on confirmed-bug paths with zero accuracy loss (measured on the planted corpus + StablecoinCDP):
  * **Supervisor demoted to a fast JSON-mode classifier.** Its routing verdict was never a soundness gate — Z3 and the EVM gatekeeper re-verify everything — so it no longer burns a 12k-thinking reasoner call on every finding-bearing function. Structured `response_format` output also eliminates the parse-failure re-invocation loop.
  * **CEGIS Z3-script repair + Foundry PoC-heal moved to a fast model.** Both outputs are re-validated deterministically (Z3 re-run / solc compile) before acceptance, so a weaker drafter cannot introduce a false verdict.
  * **Fixer thinking budget 12k → 6k.** Runs after a bug is Z3/forge-verified; it composes advisory remediation reports, not verdicts.
  * **Default `MAX_WORKERS` 2 → 8** (override: `GODEL_MAX_WORKERS`) and default per-wave budget 600 → 900 s so multi-finding functions aren't killed mid-report.
  * **Opt-in read-only fast path** (`GODEL_SKIP_READONLY=1`): functions Slither proves have no storage writes / external calls are skipped entirely — they cannot violate the state-transition invariants the Z3 harness models.
* **RAG + verifier + timeout pass (Aug 2026):** Three targeted fixes to cut the 22.8 min/contract wall time on real multi-finding contracts (measured on StablecoinCDP, 5 functions, 3 findings):
  * **RAG: batch embed + startup warmup.** The 3 query embeddings per finding now go out in a single Ollama HTTP call (`embed_batch()`) instead of 3 sequential round-trips. A `warmup_rag()` call at pipeline startup preloads the cross-encoder from HuggingFace and warms the Ollama 8b model into VRAM before any function graph spawns — eliminates the ~36s cold-start penalty that hit the first finding. Net: ~47s → ~8-10s per RAG call. Added to `Infrastructure/postgres.py`; wired into `domain/pipeline.py:run_pipeline()`.
  * **Verifier thinking budget 12k → 6k.** The verifier generates PoC exploit code that is deterministically re-validated by Z3 and the Foundry gatekeeper — a smaller thinking budget halves PoC generation time without introducing false verdicts. Same pattern as the fixer (already at 6k). Changed in `domain/pipeline.py:llm_pro`.
  * **Wave budget 900 → 1200s default.** The 900s flat budget killed multi-finding functions mid-flight (`repay`'s second finding and `redeem`'s fixer/report were cut by the timeout). The RAG + verifier savings free headroom; the higher default provides a safety margin so verified work isn't discarded. Still env-overridable via `GODEL_PER_FUNCTION_TIMEOUT`.
* **Soundness pass (Aug 2026):** Closed two known soundness gaps that affected verdict trustworthiness:
  * **Overflow bounds: uint256 capped at [0, 2^256-1].** All bounded `Int` variables in the Z3 harness now carry both a `>= 0` lower bound and a `<= 2**256 - 1` upper bound (previously unbounded above). UNSAT verdicts remain valid proofs (no counterexample in the bounded model = none in real uint256). SAT now also catches overflow bugs where arithmetic results exceed the uint256 maximum. Modular wraparound is still NOT simulated — use the existing `--wrap-probe` (BitVec-256) for exact wrap semantics. Changed in `domain/semantics.py:_reg()`.
  * **Vacuity detection in main pipeline.** After every UNSAT verdict, the executor now runs a reachability probe (`compose_reachability_script()`) that checks whether the harness model is itself satisfiable (bounds + guards + transitions without any property assertion). If the model is unsatisfiable, the UNSAT property result is vacuous — the function's preconditions contradict each other, so any property trivially holds. Vacuous results are labeled `"vacuously safe — NOT a real proof"` and tagged `NOT SAFE / INCOMPLETE` in reporting, preventing false confidence. Previously only available in invariant mode (`--invariant`). Added to `domain/semantics.py`, `domain/graph_nodes.py`, `domain/state.py`, `domain/pipeline.py`.
* **Concurrency & Thread Safety:** Upgraded `orchestrator.py` to handle 20+ parallel function graph threads simultaneously using dynamic file-naming locks in the gatekeeper sandbox.
* **CEGIS Auto-Healing Loop:** Added autonomous compiler-error feedback loops to heal failing Foundry test files across multi-iteration runs.
* **Red Herring Suppression:** Hardened Z3 path constraints to formally prove safety for bounded recursion, safe multi-variable unchecked math, and quantized rounding identities, eliminating alert fatigue.
* **Hardening pass (Aug 2026):** ElementTree-based XML extraction (fixes silent function-body truncation), AST safety gate for generated scripts, structured `forge --json` gatekeeper verdicts, worker-aware batch timeouts, absolute-path enforcement around the Slither chdir window, committed benchmark evidence ([docs/BENCHMARKS.md](docs/BENCHMARKS.md)).

### ⚡ Runtime Tuning Knobs

| Env var | Default | Effect |
|---|---|---|
| `GODEL_MAX_WORKERS` | `8` | Parallel function-graph threads per contract |
| `GODEL_ISOLATOR_MODEL` | *(unset → reasoning model)* | Fast model for the bug-hunter/isolator; every proposal is machine-verified downstream, so a fast model is safe (`deepseek-v4-flash`) |
| `GODEL_SKIP_READONLY` | `0` | `1` skips Slither-proven read-only functions (no state writes / external calls) — trades view-logic coverage for speed |
| `GODEL_PER_FUNCTION_TIMEOUT` | `1200` | Per-wave wall-clock budget in seconds |
| `GODEL_EXECUTOR_MAX_ITERATIONS` | `4` | Bounds the Z3 property refinement loop |
| `GODEL_SUPERVISOR_MAX_ITERATIONS` | `3` | Bounds the supervisor critique loop |

---
Built By Wasay. August 2026.
