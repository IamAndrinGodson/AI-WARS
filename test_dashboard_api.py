
import requests
import json

BASE_URL = "http://localhost:8000/api"

endpoints = [
    "/stats",
    "/stats/detailed",
    "/history/detailed?limit=5",
    "/realtime/status"
]

print(f"Testing API endpoints at {BASE_URL}...\n")

for ep in endpoints:
    try:
        url = f"{BASE_URL}{ep}"
        print(f"GET {url}")
        resp = requests.get(url)
        print(f"Status: {resp.status_code}")
        if resp.status_code == 200:
            try:
                data = resp.json()
                print(f"Response: {json.dumps(data, indent=2)[:500]}...") # Truncate for readability
            except:
                print("Response: <Not JSON>")
        else:
            print(f"Error: {resp.text}")
    except Exception as e:
        print(f"Failed to connect: {e}")
    print("-" * 40)
