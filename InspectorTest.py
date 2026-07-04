import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from domain.inspector import Inspector
from piyoxml import parse_solidity_to_xml

import sys
sys.stdout.reconfigure(encoding='utf-8')

load_dotenv()


# with open("solContracts/BalancerModule.sol", "r") as f:
#     Balancer = f.read()

# with open("solContracts/Slingshot.sol", "r") as f:
#     SlingShot = f.read()


with open("solContracts/README.md", "r") as f:
    Readme = f.read()
    
# with open("prompts/inspector_ReaderOutput.txt", "r") as f:
#     Reader = f.read()



# with open("prompts/inspector_isolator.txt", "r") as f:
#     Isolator = f.read()
# 3. Arbiter | PropertyGenerator | Inspector
llm_flash = ChatOpenAI(
    model="deepseek-v4-flash",
    openai_api_key=os.environ.get("DEEPSEEK_API_KEY"),
    temperature=0.0,
    openai_api_base="https://api.deepseek.com",
    extra_body={"thinking": {"type": "disabled", "budget_tokens": 32000}}
)
balancer  = parse_solidity_to_xml("solContracts/BalancerModule.sol")
slingshot  = parse_solidity_to_xml("solContracts/Slingshot.sol")
inspector = Inspector(llm_flash,llm_flash)
findings= inspector.run(f"{slingshot}\n\n\n\n\n{balancer}",Readme)

import json
print(json.dumps(findings, indent=2))
#   "\n\n\n\n\n" + Isolator

# Inspector = Inspector(agent=llm_flash)
# Inspector.QueryInspector(Readme + "\n\n\n\n\n" + slingshot + "\n\n\n\n\n" + balancer )
# print("=== Inspector OUTPUT ===")
# print(f"Findings{findings}")
# print(f"Reasoning{reasoning}")

