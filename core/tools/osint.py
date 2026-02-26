import os
import requests
from dotenv import load_dotenv
from langchain_core.tools import tool

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()

@tool
def check_ip_abuseipdb(ip_address: str) -> str:
    """
    Checks an IP address against AbuseIPDB to retrieve its reputation score and reports.
    Always use this tool if you need to determine if an IP address is malicious, a scanner, or benign.
    """
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "your_abuseipdb_api_key_here":
        return "Error: ABUSEIPDB_API_KEY is missing or invalid. Please add it to your .env file."

    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"
    }
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status()
        data = response.json()
        score = data.get("data", {}).get("abuseConfidenceScore", "Unknown")
        reports = data.get("data", {}).get("totalReports", "Unknown")
        usage_type = data.get("data", {}).get("usageType", "Unknown")
        
        return f"AbuseIPDB Result for {ip_address}: Confidence Score of {score}%. Found {reports} reports. Usage type: {usage_type}."
    except Exception as e:
        return f"Failed to query AbuseIPDB for {ip_address}: {str(e)}"

@tool
def check_virustotal_hash(file_hash: str) -> str:
    """
    Checks a file hash (MD5, SHA-1, or SHA-256) against VirusTotal.
    Use this tool when a log contains a file hash to see if it is associated with malware.
    """
    if not VT_API_KEY or VT_API_KEY == "your_virustotal_api_key_here":
        return "Error: VT_API_KEY is missing or invalid. Please add it to your .env file."

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        undetected = stats.get("undetected", 0)
        
        return f"VirusTotal Result for {file_hash}: Flagged as malicious by {malicious} vendors. Undetected by {undetected} vendors."
    except Exception as e:
        return f"Failed to query VirusTotal for {file_hash}: {str(e)}"
