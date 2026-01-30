import pandas as pd
import numpy as np
import os
import sys
import logging
import argparse
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from datetime import datetime

# Adjust path
sys.path.append(os.getcwd())
sys.path.append(os.path.join(os.getcwd(), 'src'))

from src.models.anomaly_detector import EnsembleAnomalyDetector
from src.models.kmeans_detector import KMeansAnomalyDetector
from src.features.feature_generator import FeatureEngineer
import yaml

# Configurations
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_config():
    with open('config/config.yaml', 'r') as f:
        return yaml.safe_load(f)

def load_model(path_prefix, config, is_kmeans=False):
    try:
        fe = FeatureEngineer(config)
        fe.load(f"{path_prefix}/feature_engineer.pkl")
        
        if is_kmeans:
            # K-Means uses a different loader
            ad = KMeansAnomalyDetector(config.get('models', {}).get('kmeans', {}))
            ad.load(f"{path_prefix}/kmeans_model.pkl")
        else:
            ad = EnsembleAnomalyDetector(config.get('models', {}).get('anomaly_detection', {}))
            ad.load(f"{path_prefix}/anomaly_detector")
        return fe, ad
    except Exception as e:
        logger.error(f"Failed to load model from {path_prefix}: {e}")
        return None, None

def evaluate(model_name, fe, ad, test_csv, column_map=None, is_kmeans=False):
    logger.info(f"Evaluating model: {model_name} on {test_csv}...")
    
    # Load test data
    try:
        df = pd.read_csv(test_csv)
    except Exception as e:
        logger.error(f"Could not read CSV: {e}")
        return {}

    # Map columns if provided
    if column_map:
        mapping = dict(item.split('=') for item in column_map.split(','))
        df.rename(columns=mapping, inplace=True)
        
    # Preprocessing for Feature Engineer
    if 'connection_id' not in df.columns:
        df['connection_id'] = range(len(df))
    
    if 'timestamp' not in df.columns:
        # Generate dummy timestamps
        df['timestamp'] = pd.date_range(start=datetime.now(), periods=len(df), freq='1s')
        
    # Ensure required columns exist (fill with 0 if missing to avoid hard crash, though results will be poor)
    required_cols = ['packets', 'bytes', 'flow_duration', 'protocol', 'src_port', 'dst_port']
    for col in required_cols:
        if col not in df.columns:
            # logger.warning(f"Column '{col}' missing in test data for {model_name}. Filling with 0.")
            df[col] = 0
            
    if 'src_ip' not in df.columns:
        df['src_ip'] = '0.0.0.0'
    if 'dst_ip' not in df.columns:
        df['dst_ip'] = '0.0.0.0'

    # Ensure label exists
    if 'label' not in df.columns:
        logger.warning("No 'label' column found in test data. Generating random labels for testing purposes.")
        df['label'] = np.random.randint(0, 2, size=len(df))
    
    # Preprocess (normalize labels if they are strings)
    # Assuming label 0 = benign, 1 = anomaly
    if df['label'].dtype == object:
         df['label'] = df['label'].apply(lambda x: 0 if str(x).lower() in ['benign', 'normal', '0'] else 1)
    else:
         # Ensure binary (any non-zero is 1)
         df['label'] = (df['label'] != 0).astype(int)

    y_true = df['label'].values
    
    # Inference
    try:
        start_time = datetime.now()
        
        # Check for legacy model feature mismatch (KDD/CIC-IDS)
        use_raw_features = False
        if hasattr(fe, 'scaler') and hasattr(fe.scaler, 'feature_names_in_'):
            expected = set(fe.scaler.feature_names_in_)
            # If expects 'diff_srv_rate' (raw KDD) but not 'packets_per_second' (new feature)
            if 'diff_srv_rate' in expected and 'packets_per_second' not in expected:
                use_raw_features = True
                logger.info("Detected legacy model expecting raw features. Using legacy extraction path.")

        if use_raw_features:
            # Reconstruct X using expected columns
            # Ensure all expected columns exist
            X_df = df.reindex(columns=fe.scaler.feature_names_in_, fill_value=0)
            
            # Apply encoding if present
            if hasattr(fe, 'encoders'):
                for col, le in fe.encoders.items():
                    if col in X_df.columns:
                        X_df[col] = X_df[col].astype(str)
                        # Handle unknown labels safely
                        known_labels = set(le.classes_)
                        X_df[col] = X_df[col].apply(lambda x: x if x in known_labels else list(known_labels)[0])
                        X_df[col] = le.transform(X_df[col])
            
            # Scale
            X = fe.scaler.transform(X_df)
        else:
            # Standard path
            features = fe.extract_all_features(df)
            if features.empty:
                logger.error(f"Feature extraction returned empty DataFrame for {model_name}")
                return {}
            
            X_df = fe.normalize_features(features, fit=False)
            X = X_df.values

        # Prediction
        if is_kmeans:
            # -1 is anomaly, 1 is normal
            preds = ad.predict(X)
            # Convert: -1 -> 1 (anomaly), 1 -> 0 (normal)
            y_pred = (preds == -1).astype(int)
        else:
            y_pred = ad.predict(X)
            
        duration = (datetime.now() - start_time).total_seconds()
        
        # Metrics
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        logger.info(f"Results for {model_name}: Acc={acc:.4f}, Prec={prec:.4f}, Rec={rec:.4f}, F1={f1:.4f}")
        
        return {
            "Model": model_name,
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "F1 Score": f1,
            "Latency (s)": duration,
            "Samples": len(df)
        }
    except Exception as e:
        logger.error(f"Inference failed: {e}")
        import traceback
        traceback.print_exc()
        return {}

def main():
    parser = argparse.ArgumentParser(description="Benchmark ML Models")
    args = parser.parse_args()
    
    config = load_config()
    
    # Define models and their corresponding test sets and mappings
    benchmarks = [
        {
            "name": "Synthetic",
            "model_path": "data/models",
            # Use kdd_converted for testing since sample_kdd is too small
            "test_data": "data/kdd_converted.csv", 
            "map": None,  # kdd_converted already has proper columns
            "is_kmeans": False
        },
        {
            "name": "KDD",
            "model_path": "data/models/real",
            "test_data": "data/kdd_converted.csv",
            "map": None,  # Already converted
            "is_kmeans": False
        },
        {
            "name": "CIC-IDS",
            "model_path": "data/models/cicids",
            "test_data": "data/cicids_sample.csv",
            "map": "Flow Duration=flow_duration,Total Fwd Packets=packets,Total Length of Fwd Packets=bytes,Label=label,Source Port=src_port,Destination Port=dst_port",
            "is_kmeans": False
        },
        {
            "name": "K-Means",
            "model_path": "data/models/kmeans",
            "test_data": "data/kdd_converted.csv",
            "map": None,
            "is_kmeans": True
        }
    ]
    
    results = []
    
    for bm in benchmarks:
        name = bm['name']
        path = bm['model_path']
        data_path = bm['test_data']
        mapping = bm['map']
        
        if os.path.exists(path) and os.path.exists(data_path):
            # Special handling for feature engineer mismatch:
            # The FeatureEngineer saves the 'columns' it saw during training.
            # If we pass a dataframe with different columns, it might fail.
            # The mapping helps, but we need to apply it BEFORE passing to extract features if extraction relies on specific col names.
            
            is_kmeans = bm.get('is_kmeans', False)
            fe, ad = load_model(path, config, is_kmeans=is_kmeans)
            if fe and ad:
                res = evaluate(name, fe, ad, data_path, column_map=mapping, is_kmeans=is_kmeans)
                if res:
                    results.append(res)
        else:
            logger.warning(f"Skipping {name}: Model path '{path}' or Data path '{data_path}' not found.")
    
    # Display table
    if results:
        results_df = pd.DataFrame(results)
        print("\n" + "="*60)
        print("BENCHMARK RESULTS")
        print("="*60)
        print(results_df.to_markdown(index=False))
        print("="*60)
        
        # Save to file
        results_df.to_csv("data/benchmark_results.csv", index=False)
        logger.info("Results saved to data/benchmark_results.csv")
    else:
        print("No results to display. Check logs for errors.")

if __name__ == "__main__":
    main()
