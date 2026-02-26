import streamlit as st
import pandas as pd
from database.db import get_all_incidents, update_incident_status

st.set_page_config(page_title="Autonomous AI SOC Analyst", layout="wide")

st.title("🛡️ Autonomous AI SOC Analyst Dashboard")
st.markdown("Review and triage security incidents investigated by the Multi-Agent AI System.")

# Sidebar Filters
st.sidebar.header("Filters")
status_filter = st.sidebar.selectbox("Filter by Status", ["All", "Pending", "Blocked", "Dismissed"])

# Fetch Data
if status_filter == "All":
    incidents = get_all_incidents()
else:
    incidents = get_all_incidents(status_filter)

if not incidents:
    st.info("No incidents found matching the criteria.")
else:
    for incident in incidents:
        # Determine color based on verdict
        color = "red" if incident['ai_verdict'] == "Malicious" else ("orange" if incident['ai_verdict'] == "Suspicious" else "green")
        
        with st.expander(f"[{incident['status']}] Incident #{incident['id']} - {incident['ip_address']} ({incident['timestamp']})"):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.subheader("Details")
                st.markdown(f"**IP Address:** `{incident['ip_address']}`")
                st.markdown(f"**Event Type:** `{incident['event_type']}`")
                st.markdown(f"**AI Verdict:** :{color}[**{incident['ai_verdict']}**] (Confidence: {incident['ai_confidence']}%)")
                st.markdown("**Raw Log:**")
                st.code(incident['raw_log'], language='bash')
                
                st.subheader("AI Investigation Log")
                st.text_area("Gemini's reasoning process:", incident['investigation_log'], height=200, key=f"log_{incident['id']}")
                
                if incident['remediation'] and incident['remediation'] != 'None':
                    st.subheader("Remediation Suggestion")
                    st.code(incident['remediation'], language='bash')
            
            with col2:
                st.subheader("Actions")
                st.markdown(f"**Current Status:** `{incident['status']}`")
                
                if incident['status'] == 'Pending':
                    if st.button("Approve Block", key=f"block_{incident['id']}", type="primary"):
                        update_incident_status(incident['id'], 'Blocked')
                        st.rerun()
                        
                    if st.button("Dismiss (False Positive)", key=f"dismiss_{incident['id']}"):
                        update_incident_status(incident['id'], 'Dismissed')
                        st.rerun()
