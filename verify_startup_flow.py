
import sys
import os
import asyncio
import logging
from datetime import datetime

# Add src to path
sys.path.append(os.path.join(os.getcwd(), 'src'))

# Mock uvicorn/fastapi environment
os.environ['TEST_MODE'] = '1'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VERIFY_STARTUP")

async def verify():
    logger.info("--- Starting Verification ---")
    
    # 1. Import app (triggers top-level code)
    from api.app import app, startup_event, network_monitor, get_monitor, response_engine, feature_engineer, anomaly_detector
    import api.app as app_module

    logger.info(f"Initial Globals State:")
    logger.info(f"  network_monitor: {app_module.network_monitor}")
    logger.info(f"  response_engine: {app_module.response_engine}")
    
    # 2. Run Startup Event
    logger.info("Executing startup_event()...")
    await startup_event()
    
    # 3. Check Post-Startup Globals
    logger.info(f"Post-Startup Globals State:")
    logger.info(f"  network_monitor: {app_module.network_monitor}")
    logger.info(f"  response_engine: {app_module.response_engine}")
    logger.info(f"  feature_engineer: {app_module.feature_engineer}")
    
    if app_module.network_monitor is None:
        logger.error("FAILURE: network_monitor is None after startup!")
        return
        
    # 4. Extract Callback
    monitor = app_module.network_monitor
    callback = monitor._detection_callback
    
    if callback is None:
        logger.info("Callback is None. Attempting to get it from init_network_monitor...")
        # Accessing local scope isn't easy, but we can check if it works.
        logger.error("FAILURE: NetworkMonitor has no callback set!")
        return
    else:
        logger.info("SUCCESS: Callback is set on monitor.")
        
    # 5. Simulate Real-Time Event
    logger.info("Simulating Real-Time Event...")
    test_event = [{
        'timestamp': datetime.now().isoformat(),
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'dst_port': 443,
        'protocol': 6,
        'packets': 10,
        'bytes': 500,
        'flow_duration': 1.0,
        'process': 'test.exe'
    }]
    
    try:
        results = callback(test_event)
        logger.info(f"Callback returned {len(results)} results.")
        
        if len(results) > 0:
            logger.info(f"Result 0: {results[0]}")
            
            # Check History
            history = app_module.response_engine.get_action_history()
            logger.info(f"History count: {len(history)}")
            
            if len(history) > 0:
                 logger.info("SUCCESS: Event added to history.")
            else:
                 logger.error("FAILURE: Callback returned result but History is empty!")
        else:
            logger.error("FAILURE: Callback returned Empty List!")
            
    except Exception as e:
        logger.error(f"FAILURE: Exception calling callback: {e}")

if __name__ == "__main__":
    asyncio.run(verify())
