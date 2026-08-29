"""Solidity pragma analysis for the Foundry gatekeeper.

forge-std (Test.sol / Vm.sol / StdInvariant) requires solc >= 0.8.13. Targets
pinned below that (most 2020-2023 contest code: 0.6.x / 0.7.x) cannot compile
a forge-std-based PoC suite — the Visor benchmark (pragma 0.7.6) proved this:
every verification attempt aborted at compile and real findings shipped as
"inconclusive". For those targets the gatekeeper switches to LEGACY MODE: a
self-contained cheatcode + assertion harness (test/helpers/GodelLegacyTest.sol)
that compiles on 0.6.0+.

This module decides, deterministically from the source text, whether legacy
mode is required. No LLM and no subprocess involved.
"""
import re

# forge-std's hard floor. If the target cannot be compiled with SOME version
# >= this, forge-std is unusable and the legacy harness is mandatory.
FORGE_STD_MIN = (0, 8, 13)

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_VER_RE = re.compile(r"(\d+)\s*\.\s*(\d+)(?:\s*\.\s*(\d+))?")


def _parse_version(text: str):
    m = _VER_RE.search(text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _spec_allows_modern(spec: str) -> bool:
    """True when at least one solc version >= FORGE_STD_MIN satisfies one
    pragma constraint spec (^X, exact, or an operator chain like >=A <B)."""
    spec = spec.strip()
    if not spec:
        return True  # unparseable -> assume modern, never silently block

    if spec.startswith("^"):
        v = _parse_version(spec[1:])
        if v is None:
            return True
        # ^X.Y.Z allows up to the next breaking release: (X, Y+1, 0) for 0.x,
        # (X+1, 0, 0) for X>=1.
        major, minor, _patch = v
        cap = (major, minor + 1, 0) if major == 0 else (major + 1, 0, 0)
        return cap > FORGE_STD_MIN

    # Operator chain: collect bounds.
    lower = None          # inclusive-or-not handled via value only
    upper = None
    upper_inclusive = False
    saw_operator = False
    for m in re.finditer(r"(>=|<=|>|<|=)?\s*(\d+\s*\.\s*\d+(?:\s*\.\s*\d+)?)", spec):
        op = (m.group(1) or "").strip()
        v = _parse_version(m.group(2))
        if v is None:
            continue
        if op in ("<", "<="):
            saw_operator = True
            if upper is None or v < upper or (v == upper and op == "<="):
                upper = v
                upper_inclusive = (op == "<=")
        elif op in (">", ">="):
            saw_operator = True
            lower = v if lower is None else max(lower, v)
        elif op == "=" or op == "":
            # Bare version inside a chain acts as exact pin only when it is
            # the sole token; inside an operator chain solc rejects it, so
            # treat as a lower bound to stay conservative.
            if not saw_operator and _is_single_version(spec):
                return v >= FORGE_STD_MIN
            lower = v if lower is None else max(lower, v)

    if upper is None:
        return True  # unbounded above -> some modern version satisfies
    if upper > FORGE_STD_MIN:
        return True
    return upper == FORGE_STD_MIN and upper_inclusive


def _is_single_version(spec: str) -> bool:
    return _VER_RE.fullmatch(spec.strip()) is not None


def pragma_statements(source: str) -> list:
    return [m.group(1).strip() for m in _PRAGMA_RE.finditer(source or "")]


def allows_modern_forge_std(source: str) -> bool:
    """True when forge-std (needs >=0.8.13) can compile alongside the source.
    Every pragma statement in the file must admit a modern version; with no
    pragma at all we assume modern (forge picks its default)."""
    specs = pragma_statements(source)
    if not specs:
        return True
    return all(_spec_allows_modern(s) for s in specs)


def needs_legacy_harness(source: str) -> bool:
    return not allows_modern_forge_std(source)


LEGACY_HEAL_HINT = (
    "LEGACY MODE CONSTRAINT: the target contract's pragma does not allow solc "
    ">= 0.8.13, so forge-std (forge-std/Test.sol, Vm.sol, StdInvariant, "
    "console.sol) CANNOT compile and MUST NOT be imported. Rewrite the suite "
    "as: `import \"test/helpers/GodelLegacyTest.sol\";` and inherit "
    "`GodelLegacyTest`. It provides the `vm` cheatcode object (prank, "
    "startPrank, stopPrank, deal, warp, roll, label, expectRevert, etch, "
    "addr, sign, expectEmit, store, load) and assertions (assertTrue, "
    "assertFalse, assertEq for uint256/address/bytes32/bool/string, assertGt, "
    "assertGe, assertLt, assertLe). invariant_ mode is unavailable in legacy "
    "mode — write explicit ordered test_ sequences instead. Every contract in "
    "the file, including mocks, must use a pragma compatible with the target."
)


def legacy_generation_directive(source: str) -> str:
    """Per-call directive injected into the verifier prompt when the target
    requires the legacy harness."""
    pragmas = pragma_statements(source)
    pragma_line = "; ".join(pragmas) if pragmas else "unknown"
    return f"""
<legacy_solc_mode active="true">
The target contract declares: pragma solidity {pragma_line}.
This excludes solc >= 0.8.13, therefore forge-std (forge-std/Test.sol,
Test/StdInvariant base contracts, Vm.sol, console.sol) CANNOT be compiled
with it. Generating any forge-std import guarantees a compile failure and a
wasted verification cycle. MANDATORY legacy protocol:

1. File pragma: choose a pragma the target satisfies (e.g. mirror the target's).
2. Import path: `import "test/helpers/GodelLegacyTest.sol";`
3. Test contract: `contract MyTest is GodelLegacyTest {{ ... }}` — it provides:
   - `vm` cheatcodes: prank/startPrank/stopPrank, deal, warp, roll, fee,
     label, expectRevert (no-arg / bytes4 / bytes), expectEmit, store, load,
     etch, addr, sign.
   - assertions: assertTrue(bool[, string]), assertFalse, assertEq(uint256/
     address/bytes32/bool/string), assertGt, assertGe, assertLt, assertLe.
4. NEVER import "forge-std/Test.sol" or any forge-std path. NEVER inherit
   Test or StdInvariant. NEVER use console.log. No invariant_ functions —
   express the property as an explicit ordered test_ sequence.
5. Every mock/helper contract you declare in the file must also compile under
   the target's pragma.
6. Assertion polarity law is unchanged: assert the SAFE invariant so a real
   bug makes the test FAIL.
</legacy_solc_mode>
"""
