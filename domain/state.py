from typing import TypedDict, Optional
from langchain_core.messages import SystemMessage, HumanMessage

class GraphState(TypedDict):
    user_intent_raw: str
    user_contract: str
    mode: str
    intent: str
    queries: list[str]
    findings: list[dict]
    z3_code: str
    z3_result: Optional[dict]
    status: str
    bug_report: Optional[str]
    iterations: int