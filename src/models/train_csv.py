
import pandas as pd
import numpy as np
import argparse
import logging
import yaml
import sys
import os
from datetime import datetime

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..', 'src')))

from models.anomaly_detector import EnsembleAnomalyDetector
from models.threat_classifier import ThreatClassifier
from features.feature_generator import FeatureEngineer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def train_from_csv(csv_path, output_dir, config_path, column_map=None):
    """
    Train models using data from a CSV file.
    
    Args:
        csv_path: Path to the CSV file containing training data
        output_dir: Directory to save trained models
        config_path: Path to configuration file
        column_map: Dictionary mapping CSV columns to required internal column names
    """
    logger.info(f"Loading data from {csv_path}...")
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        logger.error(f"Failed to read CSV: {e}")
        return

    # Load config
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    # Rename columns if map provided
    if column_map:
        logger.info(f"Mapping columns: {column_map}")
        df = df.rename(columns=column_map)
    
    # Ensure all required columns exist, fill with defaults if missing
    required_cols = {
        'timestamp': datetime.now().isoformat(),
        'src_ip': '0.0.0.0',
        'dst_ip': '0.0.0.0', 
        'src_port': 0,
        'dst_port': 0,
        'protocol': 6,
        'packets': 1,
        'bytes': 0,
        'flow_duration': 0.0
    }
    
    for col, default in required_cols.items():
        if col not in df.columns:
            logger.warning(f"Column '{col}' missing. Filling with default: {default}")
            df[col] = default
            
    # Add connection_id if missing
    if 'connection_id' not in df.columns:
        df['connection_id'] = range(len(df))

    # 1. Feature Engineering
    logger.info("Initializing Feature Engineer...")
    feature_engineer = FeatureEngineer(config)
    
    logger.info("Extracting features...")
    features = feature_engineer.extract_all_features(df)
    features_normalized = feature_engineer.normalize_features(features, fit=True)
    
    # Save Feature Engineer
    fe_path = os.path.join(output_dir, "feature_engineer.pkl")
    feature_engineer.save(fe_path)
    
    X = features_normalized.values
    logger.info(f"Training data shape: {X.shape}")

    # 2. Train Anomaly Detector
    logger.info("Training Anomaly Detector...")
    anomaly_detector = EnsembleAnomalyDetector(config.get('models', {}).get('anomaly_detection', {}))
    anomaly_detector.fit(X)
    
    ad_path = os.path.join(output_dir, "anomaly_detector")
    anomaly_detector.save(ad_path)

    # 3. Train Threat Classifier (Semi-supervised or utilizing labels if available)
    # If the CSV has a 'label' or 'class' column, we can use it.
    # Otherwise, we might just re-train it on this data treating it as 'normal' or skip.
    # For now, let's assume we want to retrain/update the classifier if labels exist.
    
    if 'label' in df.columns:
        logger.info("Labels found. Training Threat Classifier...")
        y = df['label'].values
        # Encode labels if necessary, this part depends on ThreatClassifier implementation details which we need to check.
        # Assuming ThreatClassifier handles raw labels or we need to encode.
        # For simplicity, if no labels, we might skip or just save the initialized one?
        # Let's create a dummy one for now if no labels, or train if labels.
        pass # To be implemented if we have labeled data logic
        
    logger.info(f"Training complete. Models saved to {output_dir}")

def parse_column_map(map_str):
    """Parse 'col=new_col,col2=new_col2' string into dict"""
    if not map_str:
        return None
    mapping = {}
    for pair in map_str.split(','):
        if '=' in pair:
            k, v = pair.split('=')
            mapping[k.strip()] = v.strip()
    return mapping

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Train models from CSV data')
    parser.add_argument('--input', required=True, help='Path to input CSV file')
    parser.add_argument('--output', required=True, help='Output directory for models')
    parser.add_argument('--config', default='config/config.yaml', help='Path to config.yaml')
    parser.add_argument('--map', help='Column mapping "csv_col=internal_col,..."')
    
    args = parser.parse_args()
    
    column_map = parse_column_map(args.map)
    
    # Create output dir if not exists
    os.makedirs(args.output, exist_ok=True)
    
    train_from_csv(args.input, args.output, args.config, column_map)
