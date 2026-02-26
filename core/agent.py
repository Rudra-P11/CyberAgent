import os
import json
from typing import TypedDict
from dotenv import load_dotenv

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import create_react_agent

from core.parser import parse_log
from core.tools.osint import check_ip_abuseipdb, check_virustotal_hash

load_dotenv()

# Define the state for our SOC Graph
class SOCState(TypedDict):
    raw_log: str
    parsed_data: dict
    osint_investigation_log: str
    verdict: str
    confidence: int
    remediation: str

# Validate API Key
api_key = os.getenv("GOOGLE_API_KEY")
if not api_key or "your_" in api_key:
    raise ValueError("GOOGLE_API_KEY is missing from .env or is still a placeholder.")

# Initialize Gemini
# Using gemini-2.0-flash as the primary reasoning engine
llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash", 
    google_api_key=api_key.strip(),
    temperature=0
)

# Initialize the tools
tools = [check_ip_abuseipdb, check_virustotal_hash]

# Create a sub-agent for OSINT investigation
osint_agent = create_react_agent(llm, tools)

def parse_node(state: SOCState):
    """Tier 0: Local Log Parsing with Gemma"""
    print("[*] Running Local Parser (Gemma)...")
    parsed = parse_log(state["raw_log"])
    return {"parsed_data": parsed}

def enrich_node(state: SOCState):
    """Tier 1: Cloud Enrichment & Tool Calling with Gemini"""
    print("[*] Running OSINT Enrichment (Gemini)...")
    parsed = state.get("parsed_data", {})
    
    # If parser failed or found nothing, we can still try to ask Gemini to look at the raw log
    prompt = f"""You are a Tier-1 SOC Analyst Investigator.
We have parsed the following entities from a log line:
{json.dumps(parsed, indent=2)}

Raw log: {state["raw_log"]}

Your task:
1. Identify any IP addresses or file hashes in the data.
2. Use your tools (check_ip_abuseipdb, check_virustotal_hash) to investigate them.
3. Summarize the findings clearly.
"""
    
    result = osint_agent.invoke({"messages": [HumanMessage(content=prompt)]})
    
    # Extract the conversation history to serve as the investigation log
    log_text = ""
    for msg in result["messages"]:
        if msg.type == "ai" and msg.content:
            log_text += f"AI: {msg.content}\n"
        elif msg.type == "tool":
            log_text += f"Tool Result ({msg.name}): {msg.content}\n"
            
    return {"osint_investigation_log": log_text}

def decision_node(state: SOCState):
    """Tier 2: Final Verdict Generation"""
    print("[*] Making Final Decision...")
    investigation = state.get("osint_investigation_log", "")
    
    prompt = f"""Based on the following OSINT investigation, provide a final verdict.
    
Investigation Log:
{investigation}

You must respond in pure JSON format with the following schema:
{{
    "verdict": "Malicious" | "Suspicious" | "Benign",
    "confidence": <integer between 0 and 100>,
    "remediation": "<suggested bash or firewall command to fix/block, or 'None' if benign>"
}}
"""
    
    response = llm.invoke([SystemMessage(content="You are a JSON-only decision bot."), HumanMessage(content=prompt)])
    
    # Clean JSON
    content = response.content.strip()
    if content.startswith("```json"):
        content = content[7:]
    if content.endswith("```"):
        content = content[:-3]
        
    try:
        decision = json.loads(content.strip())
        return {
            "verdict": decision.get("verdict", "Unknown"),
            "confidence": decision.get("confidence", 0),
            "remediation": decision.get("remediation", "None")
        }
    except Exception as e:
        print(f"Error parsing decision JSON: {e}")
        return {
            "verdict": "Error",
            "confidence": 0,
            "remediation": "Review Manually"
        }

# Build the Graph
workflow = StateGraph(SOCState)

workflow.add_node("parser", parse_node)
workflow.add_node("enricher", enrich_node)
workflow.add_node("decision_maker", decision_node)

workflow.add_edge(START, "parser")
workflow.add_edge("parser", "enricher")
workflow.add_edge("enricher", "decision_maker")
workflow.add_edge("decision_maker", END)

# Compile the graph
agent_app = workflow.compile()

if __name__ == "__main__":
    # Test the graph
    sample = "Feb 26 08:30:50 server1 sshd[1234]: Failed password for invalid user admin from 14.161.47.252 port 54321 ssh2"
    print(f"Testing Graph with log: {sample}")
    
    initial_state = {"raw_log": sample}
    final_state = agent_app.invoke(initial_state)
    
    print("\n--- Final Result ---")
    print(f"Verdict: {final_state.get('verdict')} (Confidence: {final_state.get('confidence')}%)")
    print(f"Remediation: {final_state.get('remediation')}")
    print("\n--- Investigation Log ---")
    print(final_state.get("osint_investigation_log"))