"""
Benchmark script for newly trained models.
Directly loads and evaluates the models from train_models.py
"""

import pandas as pd
import numpy as np
import os
import logging
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def clean_test_data(df: pd.DataFrame, label_column: str = 'label') -> tuple:
    """Clean test data consistently with training."""
    logger.info(f"Cleaning data... Shape: {df.shape}")
    df = df.copy()
    
    # Strip whitespace
    df.columns = df.columns.str.strip()
    
    # Handle infinity values first (CRITICAL)
    df = df.replace([np.inf, -np.inf], np.nan)
    
    # Handle missing values
    for col in df.columns:
        if df[col].dtype in ['float64', 'int64']:
            df[col] = df[col].fillna(df[col].median())
        else:
            mode_val = df[col].mode()
            df[col] = df[col].fillna(mode_val.iloc[0] if len(mode_val) > 0 else 'unknown')
    
    # Extract labels
    if label_column in df.columns:
        # Special handling for CIC-IDS labels
        if label_column == 'Label':
             y = df[label_column].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)
        else:
             y = df[label_column]
             if y.dtype == 'object':
                 y = (y != 'BENIGN').astype(int)
        
        X = df.drop(columns=[label_column])
    else:
        y = pd.Series(np.zeros(len(df)), dtype=int)
        X = df
    
    # Encode categorical columns
    for col in X.select_dtypes(include=['object']).columns:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
    
    X = X.select_dtypes(include=[np.number])
    X = X.replace([np.inf, -np.inf], 0)
    X = X.fillna(0)
    
    logger.info(f"Cleaned X shape: {X.shape}")
    return X, y


def load_and_evaluate_model(model_dir: str, test_data_path: str, label_column: str, dataset_name: str):
    """Load a trained model and evaluate on test data."""
    logger.info(f"Evaluating {dataset_name} model...")
    
    try:
        # Load model
        model_path = os.path.join(model_dir, 'anomaly_detector', 'isolation_forest.pkl')
        if not os.path.exists(model_path):
            logger.error(f"Model not found: {model_path}")
            return None
        
        model = joblib.load(model_path)
        
        # Load scaler if exists
        scaler_path = os.path.join(model_dir, 'scaler.pkl')
        scaler = joblib.load(scaler_path) if os.path.exists(scaler_path) else StandardScaler()
        
        # Load metadata for feature info
        metadata_path = os.path.join(model_dir, 'model_metadata.pkl')
        metadata = joblib.load(metadata_path) if os.path.exists(metadata_path) else {}
        
        # Load and clean test data
        df = pd.read_csv(test_data_path)
        X, y = clean_test_data(df, label_column)
        
        # Scale features
        X_scaled = scaler.fit_transform(X) if not os.path.exists(scaler_path) else scaler.transform(X)
        
        # Predict
        start_time = datetime.now()
        
        # Check if it's a classifier or anomaly detector
        if hasattr(model, 'predict_proba') or hasattr(model, 'classes_'):
            # Supervised classifier
            y_pred = model.predict(X_scaled)
        else:
            # Unsupervised (Isolation Forest returns -1 for anomalies)
            predictions = model.predict(X_scaled)
            y_pred = (predictions == -1).astype(int)
        
        latency = (datetime.now() - start_time).total_seconds()
        
        # Calculate metrics
        accuracy = accuracy_score(y, y_pred)
        precision = precision_score(y, y_pred, zero_division=0)
        recall = recall_score(y, y_pred, zero_division=0)
        f1 = f1_score(y, y_pred, zero_division=0)
        
        result = {
            'Model': dataset_name,
            'Accuracy': accuracy,
            'Precision': precision,
            'Recall': recall,
            'F1 Score': f1,
            'Latency (s)': latency,
            'Samples': len(y),
            'Algorithm': metadata.get('model_type', 'Unknown')
        }
        
        logger.info(f"  {dataset_name}: Acc={accuracy:.3f}, Prec={precision:.3f}, Rec={recall:.3f}, F1={f1:.3f}")
        return result
        
    except Exception as e:
        logger.error(f"Error evaluating {dataset_name}: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():
    logger.info("="*70)
    logger.info("BENCHMARKING TRAINED MODELS")
    logger.info("="*70)
    
    results = []
    
    # 1. KDD Model (in data/models/real)
    result = load_and_evaluate_model(
        model_dir="data/models/real",
        test_data_path="data/kdd_converted.csv",
        label_column="label",
        dataset_name="KDD"
    )
    if result:
        results.append(result)
    
    # 2. CIC-IDS Model (in data/models/cicids)
    result = load_and_evaluate_model(
        model_dir="data/models/cicids",
        test_data_path="CIC-IDS.csv",
        label_column="Label",
        dataset_name="CIC-IDS"
    )
    if result:
        results.append(result)
    
    # 3. Synthetic Model (in data/models)
    result = load_and_evaluate_model(
        model_dir="data/models",
        test_data_path="data/kdd_converted.csv",
        label_column="label",
        dataset_name="Synthetic"
    )
    if result:
        results.append(result)
    
    # Save results
    if results:
        df = pd.DataFrame(results)
        df.to_csv("data/benchmark_results.csv", index=False)
        logger.info(f"\nResults saved to data/benchmark_results.csv")
        
        # Print summary
        print("\n" + "="*90)
        print("BENCHMARK RESULTS")
        print("="*90)
        print(df[['Model', 'Algorithm', 'Accuracy', 'Precision', 'Recall', 'F1 Score']].to_string(index=False))
        print("="*90)
    else:
        logger.error("No models could be evaluated!")


if __name__ == "__main__":
    main()
