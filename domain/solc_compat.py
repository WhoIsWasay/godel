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


def _spec_interval(spec: str):
    """One pragma spec as (lower, lower_incl, upper, upper_incl); upper None
    means unbounded above. Unparseable specs return a fully open interval so
    they never block (same fail-open policy as _spec_allows_modern)."""
    spec = spec.strip()
    if not spec:
        return (None, True, None, False)

    if spec.startswith("^"):
        v = _parse_version(spec[1:])
        if v is None:
            return (None, True, None, False)
        major, minor, _patch = v
        cap = (major, minor + 1, 0) if major == 0 else (major + 1, 0, 0)
        return (v, True, cap, False)

    lower, upper = None, None
    lower_incl, upper_incl = True, False
    saw_operator = False
    for m in re.finditer(r"(>=|<=|>|<|=)?\s*(\d+\s*\.\s*\d+(?:\s*\.\s*\d+)?)", spec):
        op = (m.group(1) or "").strip()
        v = _parse_version(m.group(2))
        if v is None:
            continue
        if op in ("<", "<="):
            saw_operator = True
            if upper is None or v < upper or (v == upper and op == "<"):
                upper, upper_incl = v, op == "<="
        elif op in (">", ">="):
            saw_operator = True
            if lower is None or v > lower or (v == lower and op == ">"):
                lower, lower_incl = v, op == ">="
        else:
            if not saw_operator and _is_single_version(spec):
                return (v, True, v, True)
            if lower is None or v > lower:
                lower, lower_incl = v, True
    return (lower, lower_incl, upper, upper_incl)


def _file_interval(source: str):
    """Intersection of every pragma solidity statement in a file, or None
    when the file declares no pragma (no constraint)."""
    specs = pragma_statements(source)
    if not specs:
        return None
    lower, upper = None, None
    lower_incl, upper_incl = True, False
    for s in specs:
        l, li, u, ui = _spec_interval(s)
        if l is not None and (lower is None or l > lower or (l == lower and not li)):
            lower, lower_incl = l, li
        if u is not None and (upper is None or u < upper or (u == upper and not ui)):
            upper, upper_incl = u, ui
    return (lower, lower_incl, upper, upper_incl)


def _interval_empty(iv) -> bool:
    lower, lower_incl, upper, upper_incl = iv
    if lower is None or upper is None:
        return False
    if lower < upper:
        return False
    if lower == upper:
        return not (lower_incl and upper_incl)
    return True


def pragmas_conflict(suite_code: str, target_source: str) -> bool:
    """True when NO single solc version can compile both files together.
    forge builds the project with one version, so such a suite can never
    compile regardless of how correct its code is. Only reported when both
    sides actually declare pragmas — never block on speculation."""
    a = _file_interval(suite_code)
    b = _file_interval(target_source)
    if a is None or b is None:
        return False
    al, ali, au, aui = a
    bl, bli, bu, bui = b

    lower, lower_incl = al, ali
    if bl is not None and (lower is None or bl > lower or (bl == lower and not bli)):
        lower, lower_incl = bl, bli
    upper, upper_incl = au, aui
    if bu is not None and (upper is None or bu < upper or (bu == upper and not bui)):
        upper, upper_incl = bu, bui
    if lower is None or upper is None:
        return False
    return _interval_empty((lower, lower_incl, upper, upper_incl))


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
