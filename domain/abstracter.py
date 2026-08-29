"""domain/abstracter.py — static-analysis abstraction layer (Phase 1).

Runs Slither over one .sol file inside an isolated temp directory (crytic-compile
auto-detects a Foundry project by walking up from the CWD, so the file must be
compiled away from any foundry.toml), extracts a compact per-function CFG
abstraction, and optionally collects High/Medium impact detector results.

Everything here is deterministic Python — no LLM calls — and NON-FATAL by
contract: callers receive None on any failure and must degrade gracefully.

Public API:
    abstract_contract(sol_path) -> dict | None   (cached by content sha256)
    render_cfg_slice(analysis, focus_function) -> str  (XML-ish block for prompts)
"""

import hashlib
import contextlib
import os
import re
import shutil
import tempfile
import threading
from pathlib import Path

logger = __import__("logging").getLogger(__name__)

_CACHE: dict = {}
_CACHE_LOCK = threading.Lock()
_ABSTRACT_LOCK = threading.Lock()  # serializes chdir-sensitive work

_MAX_EXPR_CHARS = 90
_MAX_BRANCHES_PER_FUNC = 24


@contextlib.contextmanager
def _isolated_cwd(path: str):
    """Temporarily moves the PROCESS cwd to `path`, restoring it even on
    exceptions (SystemExit/BaseException included).

    Why this exists: crytic-compile auto-detects a Foundry project by walking
    UP from the CWD, so Slither must compile inside a bare tmpdir. Python has
    no per-thread cwd — this is process-global while held — hence callers MUST
    hold _ABSTRACT_LOCK around it, and every other path in the codebase must
    be absolute (pipeline.collect_sol_files enforces this)."""
    owd = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(owd)


def _content_hash(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _trim(text, limit=_MAX_EXPR_CHARS):
    text = " ".join(str(text or "").split())
    return text[:limit] + ("…" if len(text) > limit else "")


def _ntype(node) -> str:
    """Slither NodeType is a plain Enum — comparing it to its string value
    silently fails. Normalizes to the plain name ('IF', 'EXPRESSION', ...)."""
    return str(getattr(node.type, "value", node.type))


def _first_top_level_arg(text: str) -> str:
    """Returns the first comma-separated argument at bracket depth 0."""
    depth = 0
    for i, ch in enumerate(text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return text[:i]
    return text


def _branch_context(node) -> list[dict]:
    """Conditions governing execution AT this node, outermost-first.
    Each entry: {'c': <source text>, 'loop': bool} — 'loop' marks conditions
    of enclosing FOR/WHILE (IFLOOP) constructs, whose per-iteration semantics
    the encoder cannot model (callers must havock loop-dependent effects).
    Polarity is folded into the text: 'cond' via the true branch,
    'not cond' via the false branch. [] = unconditional.

    Walks the immediate-dominator chain; a node whose idom is an IF/IFLOOP
    is tagged by which son it is (index 0 = true, index 1 = false). Join
    nodes after a merge are NOT sons of the IF itself, so they walk past
    untagged — exactly right (post-merge code is unconditional)."""
    ctx: list[dict] = []
    cur = node
    seen = 0
    while cur is not None and seen < 64:
        seen += 1
        parent = getattr(cur, "immediate_dominator", None)
        if parent is None:
            break
        ptype = _ntype(parent)
        if ptype in ("IF", "IFLOOP"):
            try:
                idx = list(parent.sons).index(cur)
            except ValueError:
                idx = -1
            if idx in (0, 1):
                cond = _trim(parent.expression, 160)
                if cond:
                    ctx.append({"c": ("not " if idx == 1 else "") + cond,
                                "loop": ptype == "IFLOOP"})
        cur = parent
    ctx.reverse()
    return ctx


def _extract_function_facts(func) -> dict:
    """Pulls the CFG facts we care about from one slither Function object."""
    nodes = list(func.nodes)
    branches = []
    for n in nodes:
        if _ntype(n) in ("IF", "IFLOOP", "REQUIRE", "ASSERT"):
            expr = _trim(n.expression)
            if expr:
                branches.append({"kind": _ntype(n).lower(), "expr": expr})

    external_calls = set()
    has_external_call = False
    for n in nodes:
        for ir in n.external_calls_as_expressions:
            external_calls.add(_trim(ir, 60))
        for ir in n.high_level_calls:
            try:
                external_calls.add(_trim(ir.function.full_name, 60))
            except Exception:
                pass
    from slither.slithir.operations import (
        HighLevelCall, LowLevelCall, Send, Transfer,
        SolidityCall, Assignment,
        Return as IrReturn,
    )

    guards = []       # require/assert first-argument texts (source-level)
    assignments = []  # {'op','lhs','rhs','order'} source-level, program order
    cond_stack = []
    has_branch = any(_ntype(n) in ("IF", "IFLOOP") for n in nodes)
    first_external_call_order = None
    ev_count = 0
    for n in nodes:
        expr = str(n.expression) if n.expression else ""
        when = _branch_context(n)
        for ir in n.irs or []:
            if isinstance(ir, (HighLevelCall, LowLevelCall, Send, Transfer)):
                has_external_call = True
                if first_external_call_order is None:
                    first_external_call_order = ev_count
        if _ntype(n) in ("IF", "IFLOOP") and expr:
            cond_stack.append(_trim(expr, 160))
            ev_count += 1
        if not expr:
            continue
        try:
            # require(bool,string)(a > 0,msg) / assert(bool)(cond) — strip the
            # type signature before the argument paren.
            m = re.match(r"^(require|assert)(?:\([a-z,\s\[\]]*\))?\((.*)\)$",
                         _trim(expr, 400), re.S)
            if m and m.group(1) in ("require", "assert"):
                arg = _first_top_level_arg(m.group(2))
                if arg:
                    guards.append({"text": _trim(arg, 200), "order": ev_count,
                                   "when": when})
                    ev_count += 1
                continue
            if _ntype(n) in ("EXPRESSION", "NEW VARIABLE", "VARIABLE"):
                am = re.match(r"^(.{1,120}?)\s*(\+=|-=|\*=|/=|=)\s*(.+)$", expr, re.S)
                if am and not re.search(r"(==|!=|<=|>=)", am.group(1)[-3:]):
                    assignments.append({"op": am.group(2),
                                        "lhs": _trim(am.group(1), 80),
                                        "rhs": _trim(am.group(3), 140),
                                        "order": ev_count,
                                        "when": when})
                    ev_count += 1
        except Exception:
            continue
    returns_expr = None

    params = []
    for p in func.parameters:
        params.append({"name": p.name or f"param_{len(params)}", "type": str(p.type)})
    rets = [str(r.type) for r in func.returns]

    internal_calls = set()
    for ir in func.internal_calls:
        try:
            name = ir.function.name if hasattr(ir, "function") else str(ir)
            if not name.startswith("require") and not name.startswith("assert"):
                internal_calls.add(name)
        except Exception:
            pass

    return {
        "full_name": func.full_name,
        "visibility": func.visibility,
        "modifiers": [m.name for m in getattr(func, "modifiers", [])],
        "params": params,
        "returns_types": rets,
        "nodes": len(nodes),
        "edges": sum(len(n.sons) for n in nodes),
        "loops": sum(1 for n in nodes if n.type == "IFLOOP" or "LOOP" in str(n.type)),
        "state_writes": sorted({str(v) for n in nodes for v in n.state_variables_written}),
        "state_reads": sorted({str(v) for v in func.state_variables_read}),
        "external_calls": sorted(external_calls),
        "has_external_call": has_external_call,
        "guards": [g["text"] for g in guards],
        "assignments": assignments,
        "first_external_call_order": first_external_call_order,
        "branch_conditions_src": cond_stack,
        "has_branch": has_branch,
        "returns_expr": returns_expr,
        "internal_calls": sorted(internal_calls),
        "branches": branches[:_MAX_BRANCHES_PER_FUNC],
        "payable": func.payable,
    }


def _run_detectors(slither) -> list:
    """Runs High/Medium impact detectors on the already-built IR via
    run_detectors() (results are index-aligned with slither.detectors).
    Per-detector exceptions are swallowed inside Slither; detector noise must
    never break the audit."""
    try:
        from slither.detectors import all_detectors as ad

        candidates = [
            getattr(ad, name)
            for name in dir(ad)
            if name[0].isupper() and isinstance(getattr(ad, name), type)
        ]
        for d_cls in candidates:
            try:
                slither.register_detector(d_cls)
            except Exception:
                continue
    except Exception as e:
        logger.debug("[ABSTRACTER] detector registration failed: %s", e)
        return []

    results = []
    try:
        per_detector = slither.run_detectors()
    except Exception as e:
        logger.debug("[ABSTRACTER] run_detectors failed: %s", e)
        return []

    detectors = list(slither.detectors)
    for i, out in enumerate(per_detector or []):
        if not out or i >= len(detectors):
            continue
        d = detectors[i]
        impact = getattr(d.IMPACT, "value", None) or getattr(d.IMPACT, "name", "")
        if str(impact).upper() not in ("HIGH", "MEDIUM"):
            continue
        for item in out:
            desc = item.get("description", "") if isinstance(item, dict) else ""
            results.append({
                "check": d.ARGUMENT,
                "impact": str(impact).upper(),
                "description": _trim(desc, 160),
            })
    # dedup by (check, description)
    seen, uniq = set(), []
    for r in results:
        key = (r["check"], r["description"])
        if key not in seen:
            seen.add(key)
            uniq.append(r)
    return uniq[:40]


_SOLC_VERSION: str | None = None


def _parse_pragma(source_text: str) -> list[tuple[str, str]] | None:
    """Parses 'pragma solidity ^0.8.20;' into [(op, version), ...]."""
    m = re.search(r"pragma solidity\s+([^;]+);", source_text)
    if not m:
        return None
    constraints = []
    for tok in m.group(1).split():
        mm = re.match(r"(\^|>=|<=|>|<|=)?(\d+\.\d+\.\d+)$", tok)
        if not mm:
            continue
        op = mm.group(1) or "="
        if op == "^":
            constraints += [(">=", mm.group(2)), ("<", _bump_major(mm.group(2)))]
        else:
            constraints.append((op, mm.group(2)))
    return constraints or None


def _bump_major(version: str) -> str:
    major = int(version.split(".")[0])
    return f"{major + 1}.0.0"


def _version_satisfies(version: str, constraints: list[tuple[str, str]]) -> bool:
    def key(v):
        return tuple(int(x) for x in v.split(".")[:3])

    vk = key(version)
    for op, cv in constraints:
        ck = key(cv)
        ok = {">=": vk >= ck, "<=": vk <= ck, ">": vk > ck,
              "<": vk < ck, "=": vk == ck}.get(op, False)
        if not ok:
            return False
    return True


def _find_solc_for_source(source_path: str) -> str | None:
    """Returns a solc binary path satisfying the file's pragma, or None to use
    the system default. Resolution order:
      1. system solc (config.SOLC_BIN) if it satisfies the pragma
      2. any version already downloaded under ~/.solc-select/artifacts/
      3. opt-in auto-install via solc-select when GODEL_AUTO_INSTALL_SOLC=1
    """
    from domain.config import SOLC_BIN

    # Explicit override wins unconditionally.
    forced = os.environ.get("GODEL_SOLC_BIN")
    if forced and (Path(forced).is_file() or shutil.which(forced)):
        return forced if Path(forced).is_file() else shutil.which(forced)

    try:
        src = open(source_path, "r", encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    constraints = _parse_pragma(src)
    if not constraints:
        return None

    sys_ver = _solc_version()
    if sys_ver != "?":
        m = re.match(r"(\d+\.\d+\.\d+)", sys_ver)
        if m and _version_satisfies(m.group(1), constraints):
            return None  # default binary fine

    # solc-select artifact cache
    art_dir = Path.home() / ".solc-select" / "artifacts"
    if art_dir.is_dir():
        for d in sorted(art_dir.iterdir()):
            mm = re.match(r"solc-(\d+\.\d+\.\d+)", d.name)
            if not (mm and _version_satisfies(mm.group(1), constraints)):
                continue
            v = mm.group(1)
            for name in (f"solc-{v}.exe", f"solc-{v}"):  # windows may lack .exe
                binpath = d / name
                if binpath.is_file():
                    logger.info("[ABSTRACTER] using solc %s from solc-select cache", v)
                    return str(binpath)

    # opt-in auto-install (network!)
    if os.environ.get("GODEL_AUTO_INSTALL_SOLC", "0") in ("1", "true", "True"):
        target = f"{constraints[0][1]}"
        try:
            from solc_select.solc_select import install_artifacts, artifact_path

            install_artifacts([target])
            binpath = artifact_path(target)
            if binpath and Path(binpath).is_file():
                return str(binpath)
        except Exception as e:
            logger.warning("[ABSTRACTER] solc auto-install failed for %s: %s",
                           target, e)

    return None


def _solc_version() -> str:
    """Cached human-readable solc version (crytic hides it on this Slither
    build; the actual compile used the same binary)."""
    global _SOLC_VERSION
    if _SOLC_VERSION is None:
        try:
            import subprocess

            from domain.config import SOLC_BIN

            r = subprocess.run([SOLC_BIN, "--version"], capture_output=True,
                               text=True, timeout=15, encoding="utf-8",
                               errors="replace")
            line = (r.stdout or "").strip().splitlines()
            ver = next((l for l in line if "Version" in l), "")
            _SOLC_VERSION = _trim(ver.split("Version:", 1)[-1], 40) or "?"
        except Exception:
            _SOLC_VERSION = "?"
    return _SOLC_VERSION


def abstract_contract(sol_path: str, use_cache: bool = True) -> dict | None:
    """Full static analysis of one .sol file. Returns None on ANY failure."""
    # Anchor to an absolute path BEFORE anything else: the Slither section
    # below chdirs the process into an isolated tmpdir, and abspath() applied
    # after that would resolve relative inputs against the tmpdir (nondet-
    # erministic provenance + broken content reads).
    sol_path = os.path.abspath(sol_path)
    if not os.path.isfile(sol_path):
        return None

    try:
        digest = _content_hash(sol_path)
    except OSError:
        return None

    if use_cache:
        with _CACHE_LOCK:
            if digest in _CACHE:
                return _CACHE[digest]

    analysis = None
    tmpdir = tempfile.mkdtemp(prefix="godel_slither_")
    try:
        fname = os.path.basename(sol_path)
        shutil.copy(sol_path, os.path.join(tmpdir, fname))
        # Resolve pragma-matched solc BEFORE chdir (relative paths would break).
        solc_binary = _find_solc_for_source(sol_path)
        with _ABSTRACT_LOCK, _isolated_cwd(tmpdir):
            from slither.slither import Slither

            kwargs = {"solc": solc_binary} if solc_binary else {}
            try:
                slither = Slither(fname, **kwargs)
            except Exception as compile_err:
                # Modern vault codebases (OZ v5 + deep call chains) compile only
                # with viaIR; plain solc dies with 'Stack too deep' AFTER type
                # checking. Retry once with the viaIR profile before giving up.
                if "stack too deep" in str(compile_err).lower():
                    logger.info("[ABSTRACTER] stack-too-deep — retrying Slither with --via-ir --optimize")
                    kwargs["solc_args"] = "--via-ir --optimize"
                    slither = Slither(fname, **kwargs)
                else:
                    raise
            functions = {}
            contract_names = []
            for c in slither.contracts:
                if c.is_interface or c.is_library:
                    continue
                contract_names.append(c.name)
                for f in c.functions:
                    if f.is_constructor or not f.entry_point:
                        continue
                    # Synthetic Slither functions (constant-variable init,
                    # etc.) are IR artifacts, not callable entrypoints.
                    if f.full_name.startswith("slitherConstructor"):
                        continue
                    functions[f.full_name] = _extract_function_facts(f)

            if not contract_names:
                return None
            # Flattened files list dependencies first (OZ Context before the
            # target), so first-contract selection grabs the wrong storage
            # layout. Prefer the contract matching the file stem; otherwise
            # take the LAST one (flatten/target order), not the first.
            stem = os.path.splitext(os.path.basename(sol_path))[0].lower()
            contract_name = next(
                (n for n in contract_names if n.lower() == stem),
                contract_names[-1],
            )

            analysis = {
                "file": os.path.abspath(sol_path),
                "sha256": digest,
                "solc_version": _solc_version(),
                "contract": contract_name,
                "functions": functions,
                "detectors": _run_detectors(slither),
                "storage_layout": [
                    {"name": v.name, "type": str(v.type)}
                    for c2 in slither.contracts
                    if c2.name == contract_name
                    for v in c2.storage_variables_ordered
                ],
            }
    except Exception as e:
        logger.warning("[ABSTRACTER] static analysis failed for %s (non-fatal): %s",
                       sol_path, e)
        analysis = None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    if use_cache and analysis is not None:
        with _CACHE_LOCK:
            _CACHE[digest] = analysis
    return analysis


def _base_name(full_name_or_name: str) -> str:
    return full_name_or_name.split("(", 1)[0].strip()


def render_cfg_slice(analysis: dict | None, focus_function: str,
                     max_chars: int = 7000) -> str:
    """Renders the compact <cfg_abstraction> prompt block for the focus
    function (+1-hop internal callees). Deterministic; token-capped."""
    if not analysis:
        return ""
    functions = analysis.get("functions", {})
    focus_key = next(
        (k for k in functions if _base_name(k) == _base_name(focus_function)),
        None,
    )
    if focus_key is None:
        return ""

    ordered = [focus_key]
    for callee in functions[focus_key]["internal_calls"]:
        callee_key = next((k for k in functions if k.split("(", 1)[0] == callee), None)
        if callee_key and callee_key not in ordered:
            ordered.append(callee_key)

    lines = []
    lines.append(f'<cfg_abstraction contract="{analysis["contract"]}" '
                 f'solc="{analysis.get("solc_version", "?")}">')
    det = analysis.get("detectors", [])
    if det:
        lines.append("  <static_detector_signals>")
        for d in det[:8]:
            lines.append(f'    <signal impact="{d["impact"]}" check="{d["check"]}">{d["description"]}</signal>')
        lines.append("  </static_detector_signals>")

    for key in ordered:
        fdata = functions[key]
        tag = "focus_function_cfg" if key == focus_key else "callee_cfg"
        lines.append(f'  <{tag} signature="{key}" visibility="{fdata["visibility"]}"'
                     + ("" if not fdata["modifiers"] else f' modifiers="{" ".join(fdata["modifiers"])}"' ) +
                     f' nodes="{fdata["nodes"]}" edges="{fdata["edges"]}" loops="{fdata["loops"]}"'
                     + (" payable=\"true\"" if fdata["payable"] else "") + ">")
        if fdata["state_writes"]:
            lines.append(f'    <storage_writes>{", ".join(fdata["state_writes"])}</storage_writes>')
        if fdata["state_reads"]:
            lines.append(f'    <storage_reads>{", ".join(fdata["state_reads"][:14])}</storage_reads>')
        if fdata["external_calls"]:
            lines.append(f'    <external_calls>{", ".join(fdata["external_calls"])}</external_calls>')
        if fdata["internal_calls"]:
            lines.append(f'    <internal_calls>{", ".join(fdata["internal_calls"])}</internal_calls>')
        if fdata["branches"]:
            lines.append("    <branch_conditions>")
            for b in fdata["branches"]:
                lines.append(f'      <branch kind="{b["kind"]}">{b["expr"]}</branch>')
            lines.append("    </branch_conditions>")
        lines.append(f"  </{tag}>")
    lines.append("</cfg_abstraction>")

    block = "\n".join(lines)
    if len(block) > max_chars:
        marker = "\n...[cfg_abstraction truncated]"
        block = block[:max_chars - len(marker)] + marker
    return block
