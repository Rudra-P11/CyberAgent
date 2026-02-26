import time
import json
from core.agent import agent_app
from database.db import insert_incident

import os

# Path to the log file to monitor/process
LOG_FILE_PATH = "sample_auth.log"

def process_log(log_line):
    log_line = log_line.strip()
    if not log_line:
        return
        
    print(f"\n[{time.strftime('%H:%M:%S')}] New Log Event: {log_line}")
    print("-" * 50)
    
    # 1. Run through LangGraph pipeline
    final_state = agent_app.invoke({"raw_log": log_line})
    
    # 2. Extract results
    parsed = final_state.get('parsed_data', {})
    verdict = final_state.get('verdict')
    confidence = final_state.get('confidence')
    
    print(f"Parsed Data: {json.dumps(parsed)}")
    print(f"Verdict: {verdict} ({confidence}%)")
    
    # 3. Store in SQLite DB
    insert_incident(parsed, log_line, final_state)
    print("-> Saved to Database.")

def run_simulation():
    print(f"Starting Autonomous AI SOC Pipeline Processing: {LOG_FILE_PATH}")
    
    if not os.path.exists(LOG_FILE_PATH):
        print(f"Error: {LOG_FILE_PATH} not found.")
        return

    with open(LOG_FILE_PATH, 'r') as f:
        lines = f.readlines()
        
    for log in lines:
        process_log(log)
        time.sleep(2)  # Simulate real-time delay

if __name__ == "__main__":
    run_simulation()

if __name__ == "__main__":
    run_simulation()
