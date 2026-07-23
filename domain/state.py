from typing import TypedDict, Annotated, Sequence, Optional
from langchain_core.messages import BaseMessage
import operator

class GraphState(TypedDict):
    # ==========================================
    # GLOBAL CONTEXT (Immutable during run)
    # ==========================================
    user_contract: str
    contract_name: str
    readme_specs: str
    
    # ==========================================
    # AGENTIC MEMORY & ROUTING (Dynamic)
    # ==========================================
    # Keeps the running history of what agents have said to each other
    messages: Annotated[Sequence[BaseMessage], operator.add]
    
    # Dictates graph control flow: 'bug_hunter', 'specifier', 'gatekeeper', 'fixer', or 'FINISH'
    next_agent: str  
    
    # What function the system is actively analyzing right now
    current_focus_function: Optional[str]
    
    # The Supervisor's feedback to a sub-agent when it catches a hallucination
    supervisor_critique: Optional[str]  
    
    # ==========================================
    # EXECUTION STATE (Data passed between tools)
    # ==========================================
    mode: str
    intent: str
    queries: list[str]
    
    # Raw findings proposed by the Isolator (unverified)
    findings: list[dict]  
    
    # Final, proven bugs that actually passed the Gatekeeper/Z3
    verified_bugs: list[dict]  
    
    # ==========================================
    # ARTIFACTS
    # ==========================================
    z3_code: str
    z3_result: Optional[dict]
    slither_result: Optional[dict]
    bug_report: Optional[str]
    
    # ==========================================
    # SAFETY COUNTERS
    # ==========================================
    # Prevents infinite CEGIS or Supervisor hallucination loops
    iterations: int