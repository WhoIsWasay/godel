import json
import os
from langchain_core.messages import SystemMessage, HumanMessage
from domain.state import GraphState
from domain.config import PROMPTS_DIR


class CEGIS:
    with open(PROMPTS_DIR / "cegis_prompt.txt", "r") as f:
        SYSTEM_PROMPT = f.read()

    def __init__(self, agent, run_z3_tool):
        self.agent = agent
        self.run_z3 = run_z3_tool

