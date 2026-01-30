"""
Train CIC-IDS Model
Dedicated script for training on the full CIC-IDS dataset (225K samples)
"""

import os
import logging
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def clean_cicids_data(df: pd.DataFrame) -> tuple:
    """Clean CIC-IDS dataset with proper handling of its specific issues."""
    logger.info(f"Original shape: {df.shape}")
    
    # Strip whitespace from column names
    df.columns = df.columns.str.strip()
    
    # Find the label column
    label_col = None
    for col in df.columns:
        if 'label' in col.lower():
            label_col = col
            break
    
    if not label_col:
        raise ValueError("Could not find label column!")
    
    logger.info(f"Label column: {label_col}")
    logger.info(f"Label distribution:\n{df[label_col].value_counts()}")
    
    # Remove duplicates
    initial = len(df)
    df = df.drop_duplicates()
    logger.info(f"Removed {initial - len(df)} duplicates")
    
    # Handle infinity values
    df = df.replace([np.inf, -np.inf], np.nan)
    
    # Drop rows with too many missing values
    df = df.dropna(thresh=len(df.columns) * 0.5)  # Keep rows with at least 50% values
    
    # Fill remaining missing values
    for col in df.columns:
        if df[col].dtype in ['float64', 'int64']:
            df[col] = df[col].fillna(df[col].median())
        else:
            mode_val = df[col].mode()
            df[col] = df[col].fillna(mode_val.iloc[0] if len(mode_val) > 0 else 'unknown')
    
    # Extract labels - convert to binary (BENIGN=0, Attack=1)
    y = df[label_col].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)
    
    # Remove label column from features
    X = df.drop(columns=[label_col])
    
    # Encode any remaining object columns
    for col in X.select_dtypes(include=['object']).columns:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
    
    # Keep only numeric columns
    X = X.select_dtypes(include=[np.number])
    
    # Final cleanup
    X = X.replace([np.inf, -np.inf], 0)
    X = X.fillna(0)
    
    logger.info(f"Cleaned shape: X={X.shape}, y={y.shape}")
    logger.info(f"Binary labels: 0={sum(y==0)}, 1={sum(y==1)}")
    
    return X, y


def train_cicids_model():
    """Train models on CIC-IDS dataset."""
    logger.info("="*70)
    logger.info("TRAINING CIC-IDS MODEL")
    logger.info("="*70)
    
    # Load data
    logger.info("Loading CIC-IDS.csv...")
    df = pd.read_csv("CIC-IDS.csv", low_memory=False)
    
    # Clean data
    X, y = clean_cicids_data(df)
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    
    logger.info(f"Train: {len(X_train)}, Test: {len(X_test)}")
    
    # Train models
    models = {
        'gradient_boosting': GradientBoostingClassifier(
            n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42
        ),
        'random_forest': RandomForestClassifier(
            n_estimators=100, max_depth=20, random_state=42, n_jobs=-1, class_weight='balanced'
        )
    }
    
    results = []
    for name, model in models.items():
        logger.info(f"Training {name}...")
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
        results.append({
            'name': name,
            'model': model,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1
        })
        
        logger.info(f"  {name}: Acc={accuracy:.3f}, Prec={precision:.3f}, Rec={recall:.3f}, F1={f1:.3f}")
    
    # Select best model
    best = max(results, key=lambda x: x['f1'])
    logger.info(f"\nBest model: {best['name']} with F1={best['f1']:.4f}")
    
    # Save model
    output_dir = "data/models/cicids"
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.join(output_dir, 'anomaly_detector'), exist_ok=True)
    
    # Save model (using compatible name)
    model_path = os.path.join(output_dir, 'anomaly_detector', 'isolation_forest.pkl')
    joblib.dump(best['model'], model_path)
    
    # Save scaler
    scaler_path = os.path.join(output_dir, 'scaler.pkl')
    joblib.dump(scaler, scaler_path)
    
    # Save metadata
    metadata = {
        'dataset': 'CIC-IDS',
        'model_type': best['name'],
        'accuracy': best['accuracy'],
        'precision': best['precision'],
        'recall': best['recall'],
        'f1_score': best['f1'],
        'feature_columns': list(X.columns),
        'samples_trained': len(X_train),
        'samples_tested': len(X_test)
    }
    joblib.dump(metadata, os.path.join(output_dir, 'model_metadata.pkl'))
    
    logger.info(f"Model saved to {output_dir}")
    
    # Print summary
    print("\n" + "="*70)
    print("CIC-IDS TRAINING COMPLETE")
    print("="*70)
    print(f"Best Model: {best['name']}")
    print(f"Accuracy:   {best['accuracy']:.4f}")
    print(f"Precision:  {best['precision']:.4f}")
    print(f"Recall:     {best['recall']:.4f}")
    print(f"F1 Score:   {best['f1']:.4f}")
    print("="*70)
    
    return best


if __name__ == "__main__":
    train_cicids_model()
