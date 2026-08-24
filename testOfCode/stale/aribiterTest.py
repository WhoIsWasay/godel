import os
from dotenv import load_dotenv
from archive.arbiter import Arbiter
from langchain_openai import ChatOpenAI
load_dotenv()


llm_flash = ChatOpenAI(
    model="deepseek-v4-flash",
    openai_api_key=os.environ.get("DEEPSEEK_API_KEY"),
    openai_api_base="https://api.deepseek.com",
    extra_body={"thinking": {"type": "enabled", "budget_tokens": 16000}}
)

arbiter = Arbiter(agent=llm_flash)
resultsfromExpansion = arbiter.QueryArbiter("""Is this staking contract safe? Users deposit tokens and earn rewards over time.""")
print("=== ARBITER OUTPUT ===")
print(resultsfromExpansion)