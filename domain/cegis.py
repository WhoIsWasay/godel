

from langchain_core.messages import SystemMessage, HumanMessage

from domain.state import GraphState

class CEGIS:
    with open("prompts/cegis_prompt.txt", "r") as f:
        SYSTEM_PROMPT = f.read()




    def __init__(self, agent, run_z3_tool):
        self.agent = agent
        self.run_z3 = run_z3_tool


    def cegis_loop(self,state: GraphState) -> GraphState:
    
        iterations = 0
        max_iterations = 3
        z3_code = state["z3_code"]
    
        while iterations < max_iterations:
        
        # 1. Run Z3
            result = self.run_z3(z3_code)
        
        # 2. Terminate conditions
            if result["status"] == "unsat":
                state["status"] = "verified"
                state["z3_result"] = result
                return state
        
            if result["status"] == "sat":
            # send to Pro to check if valid
                pass
        
        # 3. Build message for Pro
            user_message = f"""
            Z3 CODE:
            {z3_code}

            RESULT STATUS: {result["status"]}
            OUTPUT: {result["output"]}
            ERROR: {result["error"]}

            INTENT: {state["intent"]}
            """
        
        # 4. Call CEGIS interpreter
            response = self.agent.invoke([
                SystemMessage(content=self.SYSTEM_PROMPT),
                HumanMessage(content=user_message)
            ])
        
        # 5. Parse response
            raw = response.content
        
            if "VERIFIED" in raw:
                state["status"] = "verified"
                return state
        
            if "BUG FOUND" in raw:
                state["status"] = "bug_found"
                state["bug_report"] = raw
                return state
        
        # 6. Otherwise it returned corrected code — iterate
            if "```python" in raw:
                z3_code = raw.split("```python")[1].split("```")[0].strip()
        
            iterations += 1
    
        # Escaped loop — needs human review
            state["status"] = "needs_review"
            state["z3_code"] = z3_code
            return state