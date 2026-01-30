import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"

def test_health():
    print(f"Checking health at {BASE_URL}/health...")
    try:
        response = requests.get(f"{BASE_URL}/health")
        if response.status_code == 200:
            print("API is Healthy!")
            print(json.dumps(response.json(), indent=2))
            return True
        else:
            print(f"Health check failed: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("Could not connect to API. Is it running?")
        return False

def test_detection():
    print(f"\nTesting detection at {BASE_URL}/detect...")
    
    # Sample normal traffic
    payload = {
        "events": [
            {
                "timestamp": datetime.now().isoformat(),
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.50",
                "src_port": 54321,
                "dst_port": 80,
                "protocol": 6,
                "packets": 50,
                "bytes": 20000,
                "flow_duration": 5.5
            },
            {
                "timestamp": datetime.now().isoformat(),
                "src_ip": "192.168.1.200", # Potential massive download/DoS
                "dst_ip": "10.0.0.50",
                "src_port": 44444,
                "dst_port": 80,
                "protocol": 6,
                "packets": 50000,
                "bytes": 100000000,
                "flow_duration": 10.0
            }
        ]
    }
    
    try:
        response = requests.post(f"{BASE_URL}/detect", json=payload)
        if response.status_code == 200:
            print("Detection successful!")
            result = response.json()
            print(json.dumps(result, indent=2))
        else:
            print(f"Detection failed: {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if test_health():
        test_detection()
