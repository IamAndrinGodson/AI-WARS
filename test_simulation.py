
import requests
import json
import time

BASE_URL = "http://localhost:8000/api"

print("Triggering simulation...")
sim_payload = {
    "attack_type": "brute_force",
    "intensity": 8,
    "duration_seconds": 2,
    "target_ip": "192.168.1.100"
}

try:
    resp = requests.post(f"{BASE_URL}/simulate", json=sim_payload)
    print(f"Simulation Status: {resp.status_code}")
    if resp.status_code == 200:
        print(f"Simulation Response: {json.dumps(resp.json(), indent=2)}")
    else:
        print(f"Simulation Error: {resp.text}")
except Exception as e:
    print(f"Simulation failed: {e}")

print("\nWaiting 2 seconds for processing...")
time.sleep(2)

print("\nChecking stats after simulation:")
try:
    resp = requests.get(f"{BASE_URL}/stats")
    print(f"Stats: {json.dumps(resp.json(), indent=2)}")
    
    resp = requests.get(f"{BASE_URL}/history/detailed?limit=5")
    hist = resp.json()
    print(f"History count: {len(hist)}")
    if len(hist) > 0:
        print(f"Latest entry: {json.dumps(hist[0], indent=2)}")
except Exception as e:
    print(f"Check failed: {e}")
