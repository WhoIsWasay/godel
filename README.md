# Gödel

**Enterprise-grade formal verification engine for smart contracts.**

Gödel bridges high-reasoning LLMs with deterministic SMT theorem proving (**Z3**) and native **Foundry EVM** sandbox fuzzing. Instead of spitting out noisy, pattern-matched false positives, Gödel translates natural language security intent and Solidity AST structures into rigorous mathematical proofs with a **0% False Positive rate**.

> *"New beginnings for software reliability."*

---

## 🏗️ Architecture Overview

Gödel abandons traditional single-threaded regex auditing in favor of a multi-agent, thread-safe graph architecture:

1. **Inspector-Isolator Agent:** Deconstructs a Solidity contract and independently spawns isolated graph threads for every single execution function concurrently.
2. **Z3 SMT Theorem Prover:** Translates function logic and invariant rules into algebraic constraints to mathematically search for counterexamples (`SAT`).
3. **Thread-Safe Gatekeeper (`gatekeeper.py`):** Compiles and tests candidate proofs inside a local EVM sandbox using dynamic UUID test naming (`QC_Verify_...`) to eliminate multi-threaded file race conditions.
4. **CEGIS Self-Healing Loop:** Automatically captures compiler errors during EVM test suites and feeds them back to the reasoning agent to self-heal test syntax.
5. **Fixer Agent:** Generates production-ready, mathematically verified Solidity remediation patches.


## 🛠️ What Changed in This Version (Changelog)

* **Concurrency & Thread Safety:** Upgraded `orchestrator.py` to handle 20+ parallel function graph threads simultaneously using dynamic file-naming locks in the gatekeeper sandbox.
* **CEGIS Auto-Healing Loop:** Added autonomous compiler-error feedback loops to heal failing Foundry test files across multi-iteration runs.
* **Red Herring Suppression:** Hardened Z3 path constraints to formally prove safety for bounded recursion, safe multi-variable unchecked math, and quantized rounding identities, eliminating alert fatigue.

---
Built By Wasay. July 2026.