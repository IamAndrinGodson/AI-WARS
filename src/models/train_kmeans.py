"""
Training Script for K-Means Clustering Anomaly Detection Model
Trains K-Means on KDD dataset with hyperparameter optimization
Uses proper FeatureEngineering pipeline for compatibility
"""

import os
import sys
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Tuple
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, silhouette_score
import joblib
import yaml
import warnings
warnings.filterwarnings('ignore')

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.models.kmeans_detector import KMeansAnomalyDetector
from src.features.feature_generator import FeatureEngineer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def load_config():
    """Load configuration"""
    config_path = os.path.join(os.path.dirname(__file__), '../../config/config.yaml')
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def load_and_prepare_data(path: str = "data/kdd_converted.csv") -> Tuple[pd.DataFrame, pd.Series]:
    """
    Load KDD dataset and prepare it for feature extraction
    """
    logger.info(f"Loading KDD data from {path}...")
    
    try:
        df = pd.read_csv(path)
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
        return None, None
        
    logger.info(f"Loaded {len(df)} rows")
    
    # Preprocessing to match FeatureEngineer expectations
    if 'connection_id' not in df.columns:
        df['connection_id'] = range(len(df))
    
    # Handle missing essential columns by filling defaults
    required_cols = {
        'timestamp': pd.Timestamp.now(), 
        'src_ip': '0.0.0.0', 
        'dst_ip': '0.0.0.0',
        'src_port': 0,
        'dst_port': 0,
        'protocol': 6,
        'packets': 0,
        'bytes': 0,
        'flow_duration': 0.0
    }
    
    for col, default in required_cols.items():
        if col not in df.columns:
            df[col] = default
            
    # Handle labels
    label_column = 'label' if 'label' in df.columns else 'class'
    
    if label_column in df.columns:
        y = df[label_column].copy()
        
        # Binary encoding: 'normal' = 0, everything else = 1
        if y.dtype == 'object':
            y = (y != 'normal').astype(int)
        else:
            y = (y != 0).astype(int)
    else:
        y = pd.Series(np.zeros(len(df)), dtype=int)
    
    return df, y


def train_kmeans_pipeline():
    """Main training pipeline using FeatureEngineer"""
    
    logger.info("="*70)
    logger.info("K-MEANS CLUSTERING MODEL TRAINING (PIPELINE)")
    logger.info("="*70 + "\n")
    
    # 1. Load Config
    config = load_config()
    
    # 2. Load Data
    df, y = load_and_prepare_data()
    if df is None:
        return
    
    # 3. Feature Engineering
    logger.info("Initializing Feature Engineer...")
    fe = FeatureEngineer(config)
    
    logger.info("Extracting features...")
    # This ensures we get exactly the features the dashboard will produce
    features = fe.extract_all_features(df)
    
    # Normalize
    logger.info("Normalizing features...")
    X_scaled = fe.normalize_features(features, fit=True).values
    
    logger.info(f"Feature shape: {X_scaled.shape}")
    
    # 4. Split Data
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # 5. Extract Normal Data for Training
    X_train_normal = X_train[y_train == 0]
    logger.info(f"Training on {len(X_train_normal)} normal samples")
    
    # 6. Train K-Means
    kmeans_config = config.get('models', {}).get('kmeans', {
        'n_clusters': 10,
        'contamination': 0.1,
        'distance_metric': 'euclidean'
    })
    
    detector = KMeansAnomalyDetector(kmeans_config)
    detector.fit(X_train_normal)
    
    # 7. Evaluate
    logger.info("Evaluating model...")
    predictions = detector.predict(X_test)
    y_pred = (predictions == -1).astype(int)
    
    f1 = f1_score(y_test, y_pred)
    acc = accuracy_score(y_test, y_pred)
    
    logger.info(f"Model Accuracy: {acc:.4f}")
    logger.info(f"Model F1 Score: {f1:.4f}")
    
    # 8. Save Everything
    output_dir = "data/models/kmeans"
    os.makedirs(output_dir, exist_ok=True)
    
    # Save Feature Engineer (CRITICAL: Saves the scaler state)
    fe_path = os.path.join(output_dir, "feature_engineer.pkl")
    fe.save(fe_path)
    
    # Save Model
    model_path = os.path.join(output_dir, "kmeans_model.pkl")
    detector.save(model_path)
    
    # Save Metadata
    metadata = {
        'model_type': 'K-Means',
        'dataset': 'KDD',
        'metrics': {'accuracy': acc, 'f1_score': f1},
        'config': kmeans_config
    }
    joblib.dump(metadata, os.path.join(output_dir, "model_metadata.pkl"))
    
    logger.info(f"All artifacts saved to {output_dir}")
    logger.info("Training Complete!")


if __name__ == "__main__":
    train_kmeans_pipeline()
