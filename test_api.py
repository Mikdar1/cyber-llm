"""
Test script for the Cybersecurity API Service

This script tests the API endpoints with sample security event data.

Usage:
    python test_api.py
"""

import requests
import json

def test_api():
    """Test the API with sample security event data."""
    
    # API endpoint
    api_url = "http://localhost:8000"
    
    # Test health check
    print("🔍 Testing health check...")
    try:
        response = requests.get(f"{api_url}/health")
        if response.status_code == 200:
            print("✅ Health check passed")
            print(f"   Response: {response.json()}")
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return
    except requests.RequestException as e:
        print(f"❌ Cannot connect to API: {e}")
        print("💡 Make sure the API service is running: uvicorn api_service:app --host 0.0.0.0 --port 8000")
        return
    
    # Sample security event data
    sample_event = {
        "adaptive_event_type": "Credential Stealing with Mimikatz",
        "base_event_type": "Virtual Memory Access",
        "component": "EDR",
        "device_name": "desktop-tqja799",
        "event_group": "DEFENSEPLUS",
        "event_time": "2025-07-03 17:27:45.710+07:00",
        "process_creation_time": "2025-07-03 16:34:21.960+07:00",
        "logged_on_user": "SYSTEM@NT AUTHORITY",
        "process_hash": "3fd857449ab04f2293985d1d770e0520466bd65c",
        "process_parent_tree": {
            "0": {
                "prcsCreationTime": "2025-07-03 16:34:19.728+07:00",
                "prcsHash": "26d9650e827f35cb38c4560ad925d2bd4a7e6f43",
                "prcsPID": 1400,
                "prcsPath": "C:\\Windows\\System32\\wininit.exe",
                "prcsUserDomain": "NT AUTHORITY",
                "prcsUserName": "SYSTEM@NT AUTHORITY",
                "prcsVerdict": "Safe"
            },
            "1": {
                "prcsCreationTime": "2025-07-03 16:34:19.809+07:00",
                "prcsHash": "2598905e5b093aa6116175a4a970a7cb21ab3231",
                "prcsPID": 1540,
                "prcsPath": "C:\\Windows\\System32\\services.exe",
                "prcsUserDomain": "NT AUTHORITY",
                "prcsUserName": "SYSTEM@NT AUTHORITY",
                "prcsVerdict": "Safe"
            },
            "2": {
                "prcsCreationTime": "2025-07-03 16:34:21.079+07:00",
                "prcsHash": "3fd857449ab04f2293985d1d770e0520466bd65c",
                "prcsPID": 4288,
                "prcsPath": "C:\\Program Files\\RustDesk\\RustDesk.exe",
                "prcsUserDomain": "NT AUTHORITY",
                "prcsUserName": "SYSTEM@NT AUTHORITY",
                "prcsVerdict": "Unknown"
            }
        },
        "process_path": "C:\\Program Files\\RustDesk\\RustDesk.exe",
        "process_user_domain": "NT AUTHORITY", 
        "process_user_name": "SYSTEM@NT AUTHORITY",
        "process_verdict": "Unknown"
    }
    
    # Test security event analysis
    print("\n🔍 Testing security event analysis...")
    try:
        response = requests.post(
            f"{api_url}/analyze",
            json=sample_event,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Analysis completed successfully")
            print(f"   Response: {json.dumps(result, indent=2)}")
        else:
            print(f"❌ Analysis failed: {response.status_code}")
            print(f"   Error: {response.text}")
            
    except requests.RequestException as e:
        print(f"❌ Request failed: {e}")
    
    print("\n🎉 API testing completed!")

if __name__ == "__main__":
    test_api()
