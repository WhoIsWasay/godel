import os
from langchain_core.messages import SystemMessage, HumanMessage
from domain.config import PROMPTS_DIR
from domain.extractor import OutputExtractor
from domain.llm_utils import call_with_retry
from domain.solc_compat import needs_legacy_harness, legacy_generation_directive, LEGACY_HEAL_HINT


_INLINE_SYSTEM_PROMPT = """<verification_engineer_directive>
    <role_definition>
        You are an elite, deterministic Defensive Verification Engineer specializing in the Foundry testing framework. Your sole objective is to generate a standalone, compilable Solidity property test suite file (`.t.sol`) that verifies an identified protocol vulnerability.
    </role_definition>

    <critical_execution_laws>
     <law id="1" title="DYNAMIC IMPORT PROTOCOL">
            You must import the target contract under test using the exact filename provided by the system context.
             You MUST strictly use this exact format: import "src/{contract_filename}";
            You are strictly FORBIDDEN from using relative paths like "../src/{contract_filename}". Forge is executed from the project root, so relative paths will break the compiler.
         </law>




        <law id="2" title="ZERO-HALLUCINATION INTERFACE & FUNCTION ALIGNMENT">
            Before instantiating or interacting with the target contract, you must parse the provided source code to map out its exact interfaces:
            - CONSTRUCTOR ALIGNMENT: Inspect the target constructor function signature. Count and verify every input argument. You must pass the exact number and type of arguments required. Do not inject or assume parameters unless they are explicitly declared in the constructor signature.
            - FUNCTION CALL ARGUMENTS: For any function called on the target contract, you MUST match its signature parameters exactly. If a function is `deposit(uint256 amount) external payable`, you CANNOT call it with empty arguments like `deposit{{value: 10}}()`. You must provide the parameter: `deposit{{value: 10}}(10)`.
            - BALANCES & STORAGE: Never assume generic ERC20/ERC721 functionality (like calling .balanceOf(user)) unless the contract inherits from an ERC standard. If user balances or ledger tracking use custom public mappings (e.g., mapping(address => uint256) public shares), you must query them directly using mapping lookup syntax: targetContract.shares(user).
        </law>

        <law id="3" title="MOCK SETUP AND MANDATORY INITIALIZATION ORDER">
            If the target contract's constructor or functions require external dependencies, abstract contracts, or custom interfaces (e.g., IOracle), you MUST explicitly declare a lightweight, functional Mock contract directly inside the test file (above your test contract suite).

            Inside your test suite's `setUp()` function, you must rigidly execute these operations in this exact order:
            1. First, deploy your Mock contracts using the `new` keyword (e.g., `MockOracle mockOracle = new MockOracle();`).
            2. Second, initialize the main contract under test, passing the deployed mock's address into its constructor arguments exactly as required (e.g., `pool = new LendingPool(address(mockOracle));`).
            NEVER leave the constructor arguments blank if the target contract requires them.
        </law>

        <law id="4" title="INVARIANT & FUZZ VERIFICATION STRATEGY">
            - Environment Setup: Provision realistic funding environments using foundry cheatcodes (vm.deal, vm.prank, vm.roll) inside your test layout based on the tool's counterexample flags.
            - FUNCTION NAMING RULE: Every single test or verification function you write MUST start with the lowercase prefix "test" (for example: `test_propertyViolationCheck()`, `test_withdrawReentrancy()`). Forge will ignore any functions that do not begin with "test".
            - MANDATORY ASSERTION POLARITY: The test harness that runs your output treats a FAILING forge test as proof the vulnerability is real, and a PASSING test as proof the property held safely. Therefore you must ALWAYS assert the safe invariant (the property that SHOULD hold if the contract were correct), never assert that the exploit succeeded. Concretely: execute the exploit sequence, then assertTrue/assertEq the safe invariant (e.g. `assertEq(attackerBalanceAfter, attackerBalanceBefore)`, `assertLe(totalWithdrawn, totalDeposited)`). If the vulnerability is real, that assertion will fail and the test run will FAIL — this is the desired, correct outcome. Do NOT write `assertTrue(exploitSucceeded)`-style tests that PASS when the bug triggers; those will be silently discarded as false negatives.
        </law>

        <law id="5" title="OUTPUT ENCAPSULATION CODE RULES">
            - Your output must consist EXCLUSIVELY of valid, clean, and compilable Solidity code enclosed inside standard markdown fences (```solidity ... ```).
            - Do not append introductory greetings, explanations, descriptions, notes, or concluding conversational prose.
        </law>

        <law id="6" title="NO STORAGE SLOT INTERFERENCE">
            NEVER guess, speculate, or hardcode literal storage slots (e.g., using `vm.store(address(pool), bytes32(uint256(5)), ...)`). You do not know the compilation layout. Instead, you must manipulate the initial state exclusively using public protocol functions (e.g., calling standard `.deposit()` or transferring tokens directly).
        </law>

        <law id="7" title="STATEFUL INVARIANT DESIGN">
            If the verification mode is set to an invariant property test, you MUST inherit from `StdInvariant`, call `targetContract(address(target))` inside the `setUp()`, and name your verification assertions using the lowercase prefix "invariant_" (e.g., `invariant_solvencyCheck()`).
        </law>

        <law id="8" title="NO FOUNDRY TEMPLATE HALLUCINATIONS">
            You are strictly forbidden from importing or referencing default Foundry template files. NEVER output `import {{Counter}} from "../src/Counter.sol";`. NEVER instantiate a `Counter` contract. You must ONLY import the target contract provided in the context.
        </law>

        <law id="9" title="MULTI-TRANSACTION EXPLOIT SEQUENCES">
            When the Extracted Tool Logs describe a state sequence, a cross-function interaction, reentrancy, or concrete counterexample values that cannot be reached in a single call, you MUST write an explicit ordered exploit SEQUENCE inside a `test_` function instead of relying on invariant fuzzing:
            1. In `setUp()`, deploy and fund all actors (use `vm.deal` for ETH, mock tokens for ERC20).
            2. In the test body, execute the transactions IN ORDER exactly as the trace describes, one call per line, using `vm.prank(attacker)` / `vm.startPrank` / `vm.stopPrank` when the acting account matters.
            3. Reentrancy traces: implement the attacker callback contract explicitly and trigger it via the external call site named in the trace.
            4. After the final transaction, assert the SAFE invariant per Law 4 (a real bug then makes the test FAIL).
            Prefer this explicit-sequence style whenever the trace provides concrete values; use fuzz/invariant mode only for single-call properties.
        </law>
    </critical_execution_laws>
</verification_engineer_directive>"""


def _load_verifier_system_prompt() -> str:
    """Loads verifier_prompt.txt from disk; falls back to inline if unavailable."""
    try:
        with open(PROMPTS_DIR / "verifier_prompt.txt", "r", encoding="utf-8") as f:
            content = f.read().strip()
        if content:
            return content
    except OSError:
        pass
    return _INLINE_SYSTEM_PROMPT


class PropertyVerifierAgent:
    def __init__(self, agent_llm, heal_llm=None):
        self.llm = agent_llm
        self.heal_llm = heal_llm or agent_llm
        self.system_prompt = _load_verifier_system_prompt()

    def generate_test_suite(self, finding: dict, result_state: dict, contract_code: str, contract_filename: str) -> str:
        func_name = finding.get("target_function", "unknown")
        mode = result_state.get("mode", "standard")

        z3_result = result_state.get("z3_result")
        if z3_result and z3_result.get("status") == "sat" and z3_result.get("output"):
            facts = str(OutputExtractor.parse_z3_counterexample(z3_result["output"]))
            cex = z3_result.get("counterexample") or {}
            if isinstance(cex, dict) and cex.get("assignments"):
                facts += "\nCONCRETE COUNTEREXAMPLE ASSIGNMENTS (use these exact values in the sequence): " + \
                         ", ".join(f"{k}={v}" for k, v in sorted(cex["assignments"].items()))
        else:
            raw_report = result_state.get("bug_report", "")
            facts = str(OutputExtractor.parse_slither_json(raw_report, func_name))

        legacy = needs_legacy_harness(contract_code)
        legacy_block = legacy_generation_directive(contract_code) if legacy else ""

        user_content = f"""TARGET CONTRACT FILENAME: {contract_filename}
{legacy_block}
<contract>
{contract_code}
</contract>

<solver_trace>
Target Function: {func_name}
Verification Mode: {mode}
Extracted Tool Logs: {facts}
</solver_trace>

Read the contract source inside <contract> tags, parse its true interface bounds per the system-prompt laws, and generate the complete standalone Foundry property test code (.t.sol) that imports "src/{contract_filename}"."""

        response = call_with_retry(
            lambda: self.llm.invoke([
                SystemMessage(content=self.system_prompt),
                HumanMessage(content=user_content),
            ])
        )
        return self._clean_markdown(response.content.strip())


    def heal_test_suite(self, broken_code: str, error_log: str, legacy: bool = False) -> str:
        """CEGIS loop integration: Feed errors back to the model for self-healing."""
        legacy_reminder = f"\n\n{LEGACY_HEAL_HINT}" if legacy else ""
        feedback_prompt = f"""The Foundry test code you generated failed to compile. 
You must fix the errors detailed below and return a corrected, fully compilable version.

### BROKEN CODE:
```solidity
{broken_code}
COMPILER ERROR:
{error_log}
{legacy_reminder}
Review the original target contract interface, correct the syntax/arguments according to the exact error, and return ONLY the corrected raw Solidity code inside markdown fences."""
        response = call_with_retry(lambda: self.heal_llm.invoke(feedback_prompt))
        return self._clean_markdown(response.content.strip())

    def _clean_markdown(self, content: str) -> str:
        if "```solidity" in content:
            return content.split("```solidity")[1].split("```")[0].strip()
        elif "```" in content:
            return content.split("```")[1].split("```")[0].strip()
        return content