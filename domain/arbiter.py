
import json
from langchain_core.messages import SystemMessage, HumanMessage


class Arbiter:
    with open("prompts/arbiter_prompt.txt", "r") as f:
        SYSTEM_PROMPT = f.read()


    def __init__(self, agent):
        self.agent = agent


  
    def QueryArbiter(self,query: str) -> dict:
        response = self.agent.invoke([
            SystemMessage(content=self.prompt),
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





# from langchain.agents import create_agent

# def get_weather(city: str) -> str:
#     """Get weather for a given city."""
#     return f"It's always sunny in {city}!"

# agent = create_agent(
#     model="openai:gpt-5.5",
#     tools=[get_weather],
#     system_prompt="You are a helpful assistant",
# )

# result = agent.invoke(
#     {"messages": [{"role": "user", "content": "What's the weather in San Francisco?"}]}
# )
# print(result["messages"][-1].content_blocks)