import sys
import os
import pandas as pd
import json
import yaml
import numpy as np

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from features.feature_generator import FeatureEngineer

def show_sample():
    # 1. Raw Input
    raw_event = {
        "timestamp": "2024-01-30T10:00:00Z",
        "src_ip": "192.168.1.105",
        "dst_ip": "10.0.0.50",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": 6,
        "packets": 50,
        "bytes": 25000,
        "flow_duration": 2.5
    }
    
    print("=== 1. RAW DATA (What the API receives) ===")
    print(json.dumps(raw_event, indent=2))
    print("\n")
    
    # 2. Preprocessing
    df = pd.DataFrame([raw_event])
    df['connection_id'] = [0] # Dummy ID for single event
    
    # Load config
    try:
        with open('config/config.yaml', 'r') as f:
            config = yaml.safe_load(f)
    except:
        # Fallback config if file not found
        config = {'features': {'network': True, 'temporal': True}}

    # 3. Feature Engineering
    engineer = FeatureEngineer(config)
    
    # Try to load fitted scaler if available, otherwise use fresh (just for demo)
    try:
        engineer.load('data/models/feature_engineer.pkl')
    except:
        pass

    features = engineer.extract_all_features(df)
    
    print("=== 2. ENGINEERED FEATURES (What the ML model sees) ===")
    print(f"Total Features: {features.shape[1]}")
    print("-" * 60)
    print(f"{'Feature Name':<30} | {'Value':<15}")
    print("-" * 60)
    
    for col in features.columns:
        val = features.iloc[0][col]
        print(f"{col:<30} | {val:<15.4f}")
        
    print("-" * 60)

if __name__ == "__main__":
    show_sample()
