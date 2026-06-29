
import json
from langchain_core.messages import SystemMessage, HumanMessage


class Arbiter:
    with open("prompts/arbiter_prompt.txt", "r") as f:
        SYSTEM_PROMPT = f.read()


    def __init__(self, agent):
        self.agent = agent


  
    def QueryArbiter(self,query: str) -> dict:
        response = self.agent.invoke([
            SystemMessage(content=self.SYSTEM_PROMPT),
            HumanMessage(content=query),
        ])
        
        raw = response.content.strip()
        # Strip markdown fences if model wraps in ```json
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        
        parsed = json.loads(raw.strip())
        return parsed





