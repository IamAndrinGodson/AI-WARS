"""
Multi-Algorithm Model Training Script
Trains multiple models on each dataset, evaluates them, and selects the best performer.
"""

import os
import sys
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Any, Tuple, List
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import joblib
import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ========== DATA CLEANING ==========

def clean_data(df: pd.DataFrame, label_column: str = 'label') -> Tuple[pd.DataFrame, pd.Series]:
    """Clean and prepare data for training."""
    logger.info(f"Cleaning data with {len(df)} rows...")
    
    # Make a copy
    df = df.copy()
    
    # Remove duplicates
    initial_rows = len(df)
    df = df.drop_duplicates()
    logger.info(f"Removed {initial_rows - len(df)} duplicate rows")
    
    # Handle missing values - fill numeric with median, categorical with mode
    for col in df.columns:
        if df[col].dtype in ['float64', 'int64']:
            df[col] = df[col].fillna(df[col].median())
        else:
            df[col] = df[col].fillna(df[col].mode().iloc[0] if len(df[col].mode()) > 0 else 'unknown')
    
    # Encode categorical columns
    label_encoders = {}
    for col in df.select_dtypes(include=['object']).columns:
        if col != label_column:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            label_encoders[col] = le
    
    # Extract labels
    if label_column in df.columns:
        y = df[label_column].copy()
        X = df.drop(columns=[label_column])
        
        # Convert labels to binary if needed (0=normal, 1=attack)
        if y.dtype == 'object':
            # For CIC-IDS: BENIGN=0, everything else=1
            y = (y != 'BENIGN').astype(int)
        else:
            y = y.astype(int)
    else:
        logger.warning(f"Label column '{label_column}' not found! Using dummy labels.")
        y = pd.Series(np.zeros(len(df)), dtype=int)
        X = df
    
    # Remove any remaining non-numeric columns
    X = X.select_dtypes(include=[np.number])
    
    # Replace inf values
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)
    
    logger.info(f"Cleaned data: {len(X)} samples, {X.shape[1]} features")
    logger.info(f"Class distribution: {dict(y.value_counts())}")
    
    return X, y


# ========== MODEL CONFIGURATIONS ==========

MODEL_CONFIGS = {
    'isolation_forest_conservative': {
        'class': IsolationForest,
        'params': {'n_estimators': 200, 'contamination': 0.05, 'random_state': 42, 'n_jobs': -1},
        'is_classifier': False
    },
    'isolation_forest_balanced': {
        'class': IsolationForest,
        'params': {'n_estimators': 200, 'contamination': 0.15, 'random_state': 42, 'n_jobs': -1},
        'is_classifier': False
    },
    'isolation_forest_aggressive': {
        'class': IsolationForest,
        'params': {'n_estimators': 300, 'contamination': 0.30, 'random_state': 42, 'n_jobs': -1},
        'is_classifier': False
    },
    'random_forest': {
        'class': RandomForestClassifier,
        'params': {'n_estimators': 100, 'max_depth': 20, 'random_state': 42, 'n_jobs': -1, 'class_weight': 'balanced'},
        'is_classifier': True
    },
    'gradient_boosting': {
        'class': GradientBoostingClassifier,
        'params': {'n_estimators': 100, 'learning_rate': 0.1, 'max_depth': 5, 'random_state': 42},
        'is_classifier': True
    }
}


# ========== TRAINING FUNCTIONS ==========

def train_and_evaluate(X_train, X_test, y_train, y_test, model_name: str, config: Dict) -> Dict[str, Any]:
    """Train a model and evaluate its performance."""
    logger.info(f"Training {model_name}...")
    
    try:
        # Initialize model
        model = config['class'](**config['params'])
        
        if config['is_classifier']:
            # Supervised classifier
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
        else:
            # Unsupervised (Isolation Forest)
            model.fit(X_train)
            # IF returns -1 for anomalies, 1 for normal
            predictions = model.predict(X_test)
            y_pred = (predictions == -1).astype(int)  # Convert to 1=anomaly, 0=normal
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
        results = {
            'model_name': model_name,
            'model': model,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'config': config['params']
        }
        
        logger.info(f"  {model_name}: Acc={accuracy:.3f}, Prec={precision:.3f}, Rec={recall:.3f}, F1={f1:.3f}")
        return results
        
    except Exception as e:
        logger.error(f"Error training {model_name}: {e}")
        return {
            'model_name': model_name,
            'model': None,
            'accuracy': 0, 'precision': 0, 'recall': 0, 'f1_score': 0,
            'error': str(e)
        }


def train_all_models(X: pd.DataFrame, y: pd.Series, dataset_name: str) -> List[Dict]:
    """Train all models on a dataset and return results."""
    logger.info(f"\n{'='*60}")
    logger.info(f"Training models for: {dataset_name}")
    logger.info(f"{'='*60}")
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y if len(y.unique()) > 1 else None
    )
    
    logger.info(f"Train size: {len(X_train)}, Test size: {len(X_test)}")
    
    results = []
    for model_name, config in MODEL_CONFIGS.items():
        result = train_and_evaluate(X_train, X_test, y_train, y_test, model_name, config)
        result['scaler'] = scaler
        result['feature_columns'] = list(X.columns)
        results.append(result)
    
    return results


def select_best_model(results: List[Dict]) -> Dict:
    """Select the best performing model based on F1 score."""
    valid_results = [r for r in results if r.get('model') is not None]
    if not valid_results:
        return None
    
    best = max(valid_results, key=lambda x: x['f1_score'])
    logger.info(f"\nBest model: {best['model_name']} with F1={best['f1_score']:.3f}")
    return best


def save_model(result: Dict, output_dir: str, dataset_name: str):
    """Save the best model and associated components."""
    os.makedirs(output_dir, exist_ok=True)
    
    # Create anomaly_detector subdirectory (matches existing structure)
    ad_dir = os.path.join(output_dir, 'anomaly_detector')
    os.makedirs(ad_dir, exist_ok=True)
    
    # Save model
    model_path = os.path.join(ad_dir, 'isolation_forest.pkl')  # Keep compatible name
    joblib.dump(result['model'], model_path)
    logger.info(f"Saved model to {model_path}")
    
    # Save scaler
    scaler_path = os.path.join(output_dir, 'scaler.pkl')
    joblib.dump(result['scaler'], scaler_path)
    
    # Save metadata
    metadata = {
        'dataset': dataset_name,
        'model_type': result['model_name'],
        'accuracy': result['accuracy'],
        'precision': result['precision'],
        'recall': result['recall'],
        'f1_score': result['f1_score'],
        'config': result['config'],
        'feature_columns': result['feature_columns']
    }
    metadata_path = os.path.join(output_dir, 'model_metadata.pkl')
    joblib.dump(metadata, metadata_path)
    
    logger.info(f"Saved all components to {output_dir}")


# ========== DATASET LOADING ==========

def load_kdd_data() -> Tuple[pd.DataFrame, pd.Series]:
    """Load and clean KDD dataset."""
    path = "data/kdd_converted.csv"
    logger.info(f"Loading KDD data from {path}...")
    df = pd.read_csv(path)
    return clean_data(df, label_column='label')


def load_cicids_data() -> Tuple[pd.DataFrame, pd.Series]:
    """Load and clean CIC-IDS dataset."""
    path = "data/cicids_sample.csv"
    logger.info(f"Loading CIC-IDS data from {path}...")
    df = pd.read_csv(path)
    return clean_data(df, label_column='Label')


def generate_synthetic_data(base_df: pd.DataFrame, base_y: pd.Series, n_samples: int = 10000) -> Tuple[pd.DataFrame, pd.Series]:
    """Generate synthetic training data from base dataset."""
    logger.info(f"Generating {n_samples} synthetic samples...")
    
    # Resample with replacement
    indices = np.random.choice(len(base_df), size=min(n_samples, len(base_df)), replace=True)
    X_synthetic = base_df.iloc[indices].copy()
    y_synthetic = base_y.iloc[indices].copy()
    
    # Add some noise to make it synthetic
    noise = np.random.normal(0, 0.1, X_synthetic.shape)
    X_synthetic = X_synthetic + noise
    
    return X_synthetic, y_synthetic


# ========== MAIN ==========

def main():
    logger.info("="*70)
    logger.info("MULTI-ALGORITHM MODEL TRAINING")
    logger.info("="*70)
    
    all_results = []
    
    # 1. Train on KDD Dataset
    try:
        X_kdd, y_kdd = load_kdd_data()
        kdd_results = train_all_models(X_kdd, y_kdd, "KDD")
        best_kdd = select_best_model(kdd_results)
        if best_kdd:
            save_model(best_kdd, "data/models/real", "KDD")
            all_results.append(('KDD', best_kdd))
    except Exception as e:
        logger.error(f"Error with KDD dataset: {e}")
    
    # 2. Train on CIC-IDS Dataset
    try:
        X_cicids, y_cicids = load_cicids_data()
        cicids_results = train_all_models(X_cicids, y_cicids, "CIC-IDS")
        best_cicids = select_best_model(cicids_results)
        if best_cicids:
            save_model(best_cicids, "data/models/cicids", "CIC-IDS")
            all_results.append(('CIC-IDS', best_cicids))
    except Exception as e:
        logger.error(f"Error with CIC-IDS dataset: {e}")
    
    # 3. Train Synthetic Model (based on KDD)
    try:
        X_synthetic, y_synthetic = generate_synthetic_data(X_kdd, y_kdd)
        synthetic_results = train_all_models(X_synthetic, y_synthetic, "Synthetic")
        best_synthetic = select_best_model(synthetic_results)
        if best_synthetic:
            save_model(best_synthetic, "data/models", "Synthetic")
            all_results.append(('Synthetic', best_synthetic))
    except Exception as e:
        logger.error(f"Error with Synthetic dataset: {e}")
    
    # Print summary
    logger.info("\n" + "="*70)
    logger.info("TRAINING COMPLETE - SUMMARY")
    logger.info("="*70)
    print("\n{:<15} {:<30} {:<10} {:<10} {:<10} {:<10}".format(
        "Dataset", "Best Model", "Accuracy", "Precision", "Recall", "F1 Score"
    ))
    print("-"*85)
    for dataset, result in all_results:
        print("{:<15} {:<30} {:<10.3f} {:<10.3f} {:<10.3f} {:<10.3f}".format(
            dataset, 
            result['model_name'],
            result['accuracy'],
            result['precision'],
            result['recall'],
            result['f1_score']
        ))
    
    logger.info("\nAll models saved! Run benchmark.py to verify performance.")


if __name__ == "__main__":
    main()
