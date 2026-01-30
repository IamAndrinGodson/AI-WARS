
import sys
import os
import logging
from datetime import datetime

# Add src to path
sys.path.append(os.path.join(os.getcwd(), 'src'))

from response.response_engine import ResponseEngine, ResponseAction

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_flow():
    print("Testing Real-Time Data Flow...")
    
    # 1. Initialize Response Engine
    config = {'automation': {'enabled': True}, 'actions': {}}
    engine = ResponseEngine(config)
    
    # 2. Simulate Event (from NetworkMonitor)
    event = {
        'timestamp': datetime.now().isoformat(),
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'dst_port': 443,
        'protocol': 6,
        'source': 'realtime', # This is what NetworkMonitor sends
        'process': 'chrome.exe'
    }
    
    # 3. Simulate Detection Callback (from app.py)
    # This matches the structure in app.py exactly
    result = {
        'threat_id': 'RT-TEST-001',
        'timestamp': event['timestamp'],
        'threat_class': 'unknown',
        'risk_score': 0.0,
        'severity': 'low',
        'action': 'monitor',
        'source': 'realtime' # This is in valid result
    }
    
    risk_assessment = {'risk_score': 0.0, 'severity': 'low'}
    
    # Execute Response (What app.py does)
    # passing event + extra fields as threat_details
    threat_details = {**event, 'threat_class': 'unknown', 'source': 'realtime'}
    
    engine.execute_response(
        result['threat_id'],
        risk_assessment,
        threat_details,
        require_approval=False
    )
    
    # 4. Check History (What get_detailed_stats does)
    history = engine.get_action_history()
    print(f"History items: {len(history)}")
    
    if len(history) > 0:
        h = history[0]
        # Inspect structure
        res = h.get('result', {})
        details = res.get('threat_details', {})
        source = details.get('source')
        
        print(f"Retrieved Source: '{source}'")
        
        if source == 'realtime':
            print("SUCCESS: Source field is correctly preserved.")
        else:
            print(f"FAILURE: Source field missmatch. Got '{source}'")
            print(f"Full Entry: {h}")
    else:
        print("FAILURE: No history recorded.")

if __name__ == "__main__":
    test_flow()
