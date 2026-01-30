import requests
import json
import time
import random
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Configuration
API_URL = "http://localhost:8000/detect"
DELAY_BETWEEN_REQUESTS = 2.0  # seconds
NUM_THREADS = 1 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_random_ip(prefix="192.168"):
    return f"{prefix}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_traffic_payload(attack_type=None):
    """Generate a payload with 1-5 network events"""
    events = []
    num_events = random.randint(1, 5)
    
    timestamp = datetime.now().isoformat()
    
    for _ in range(num_events):
        event = {
            "timestamp": timestamp,
            "src_ip": generate_random_ip("192.168.1"),
            "dst_ip": "10.0.0.50", # Critical server
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 22, 3306]),
            "protocol": 6, # TCP
            "packets": random.randint(10, 1000),
            "bytes": random.randint(1000, 50000),
            "flow_duration": random.uniform(0.1, 30.0)
        }
        
        # Inject attack patterns if specified
        if attack_type == "dos":
            event["packets"] = random.randint(50000, 100000)
            event["bytes"] = random.randint(1000000, 5000000)
            event["flow_duration"] = random.uniform(0.1, 2.0)
            event["src_ip"] = generate_random_ip("10.10.10") # Spooofed external
            
        elif attack_type == "port_scan":
            event["dst_port"] = random.randint(1, 1024)
            event["packets"] = 2
            event["bytes"] = 120
            event["flow_duration"] = 0.01
            
        elif attack_type == "brute_force":
            event["dst_port"] = 22
            event["packets"] = random.randint(5, 10)
            event["bytes"] = random.randint(200, 500)
            event["flow_duration"] = 0.5
            
        events.append(event)
        
    return {"events": events}

def send_traffic():
    """Send a single batch of traffic"""
    # 20% chance of attack traffic
    attack_type = None
    if random.random() < 0.2:
        attack_type = random.choice(["dos", "port_scan", "brute_force"])
        
    payload = generate_traffic_payload(attack_type)
    
    try:
        response = requests.post(API_URL, json=payload)
        if response.status_code == 200:
            result = response.json()
            anomalies = result.get('summary', {}).get('anomalies_detected', 0)
            status = f"Anomaly: {anomalies}" if anomalies > 0 else "Normal"
            logger.info(f"Sent {len(payload['events'])} events [{attack_type or 'normal'}]. API: {status}")
        else:
            logger.error(f"API Error: {response.status_code} - {response.text}")
            
    except Exception as e:
        logger.error(f"Connection Error: {e}")

def run_generator():
    logger.info(f"Starting traffic generator. Target: {API_URL}")
    logger.info("Press Ctrl+C to stop.")
    
    try:
        while True:
            send_traffic()
            time.sleep(DELAY_BETWEEN_REQUESTS + random.uniform(-0.5, 0.5))
            
    except KeyboardInterrupt:
        logger.info("Traffic generator stopped.")

if __name__ == "__main__":
    run_generator()
