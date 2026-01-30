
import os
import sys
import logging
import yaml
import joblib
from pathlib import Path

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.getcwd())))

from src.models.anomaly_detector import EnsembleAnomalyDetector
from src.features.feature_generator import FeatureEngineer
from src.models.kmeans_detector import KMeansAnomalyDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_config():
    with open('config/config.yaml', 'r') as f:
        return yaml.safe_load(f)

def test_load_ensemble(name, path, config):
    print(f"\n--- Testing {name} at {path} ---")
    
    if not os.path.exists(path):
        print(f"Path does not exist: {path}")
        return

    # test FE
    try:
        fe_path = f"{path}/feature_engineer.pkl"
        print(f"Loading FE from {fe_path}")
        fe = FeatureEngineer(config)
        fe.load(fe_path)
        print("FE Loaded OK")
    except Exception as e:
        print(f"FE Load Failed: {e}")

    # test AD
    try:
        ad_path = f"{path}/anomaly_detector"
        print(f"Loading AD from {ad_path}")
        
        # KEY DEBUG: Check what config we are passing
        ad_config = config.get('models', {}).get('anomaly_detection', {})
        print(f"AD Config passed to init: {ad_config}")
        
        ad = EnsembleAnomalyDetector(ad_config)
        print(f"AD Initialized. Detectors: {list(ad.detectors.keys())}")
        
        ad.load(ad_path)
        print("AD Loaded OK")
    except Exception as e:
        print(f"AD Load Failed: {e}")
        import traceback
        traceback.print_exc()

def main():
    try:
        config = load_config()
        test_load_ensemble("KDD", "data/models/real", config)
        test_load_ensemble("CIC-IDS", "data/models/cicids", config)
    except Exception as e:
        print(f"Main failed: {e}")

if __name__ == "__main__":
    main()
