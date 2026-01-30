"""
Main Training Script
Orchestrates the complete training pipeline for all models
"""

import logging
import argparse
from pathlib import Path
import yaml
import numpy as np
import pandas as pd
from datetime import datetime

import sys
sys.path.append('src')

from features.feature_generator import FeatureEngineer
from models.anomaly_detector import EnsembleAnomalyDetector
from models.threat_classifier import ThreatClassifier

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/training.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


class TrainingPipeline:
    """Complete training pipeline orchestrator"""
    
    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.feature_engineer = FeatureEngineer(self.config)
        self.anomaly_detector = None
        self.threat_classifier = None
        
    def load_data(self, data_path: str) -> pd.DataFrame:
        """Load training data"""
        logger.info(f"Loading data from {data_path}")
        
        path = Path(data_path)
        
        if path.is_file():
            # Single file
            if path.suffix == '.parquet':
                df = pd.read_parquet(path)
            elif path.suffix == '.csv':
                df = pd.read_csv(path)
            else:
                raise ValueError(f"Unsupported file format: {path.suffix}")
        else:
            # Directory - load all parquet files
            files = list(path.glob('*.parquet'))
            if not files:
                raise ValueError(f"No parquet files found in {data_path}")
            
            dfs = [pd.read_parquet(f) for f in files]
            df = pd.concat(dfs, ignore_index=True)
        
        logger.info(f"Loaded {len(df)} records with {len(df.columns)} columns")
        return df
    
    def prepare_features(self, df: pd.DataFrame) -> tuple:
        """Extract and prepare features"""
        logger.info("Extracting features...")
        
        # Extract features
        features = self.feature_engineer.extract_all_features(df)
        
        # Normalize
        features_normalized = self.feature_engineer.normalize_features(features)
        
        # Get labels if available
        labels = df['label'] if 'label' in df.columns else None
        
        logger.info(f"Prepared {features_normalized.shape[1]} features")
        
        return features_normalized, labels
    
    def train_anomaly_detectors(self, X: np.ndarray):
        """Train anomaly detection models"""
        logger.info("="*60)
        logger.info("Training Anomaly Detection Models")
        logger.info("="*60)
        
        model_config = self.config.get('models', {})
        anomaly_config = model_config.get('anomaly_detection', {})
        
        self.anomaly_detector = EnsembleAnomalyDetector(anomaly_config)
        self.anomaly_detector.fit(X)
        
        # Save models
        model_path = 'data/models/anomaly_detector'
        self.anomaly_detector.save(model_path)
        logger.info(f"Anomaly detection models saved to {model_path}")
        
    def train_threat_classifier(self, X: np.ndarray, y: np.ndarray):
        """Train threat classification models"""
        logger.info("="*60)
        logger.info("Training Threat Classification Models")
        logger.info("="*60)
        
        if y is None:
            logger.warning("No labels available, skipping threat classifier training")
            return
        
        model_config = self.config.get('models', {})
        classification_config = model_config.get('classification', {})
        
        self.threat_classifier = ThreatClassifier(classification_config)
        results = self.threat_classifier.fit(X, y)
        
        logger.info("Classification Results:")
        for model_name, metrics in results.items():
            logger.info(f"  {model_name}:")
            logger.info(f"    Train Accuracy: {metrics['train_score']:.4f}")
            logger.info(f"    Val Accuracy: {metrics['val_score']:.4f}")
            if 'cv_mean' in metrics:
                logger.info(f"    CV Score: {metrics['cv_mean']:.4f} (+/- {metrics['cv_std']:.4f})")
        
        # Save models
        model_path = 'data/models/threat_classifier'
        self.threat_classifier.save(model_path)
        logger.info(f"Threat classification models saved to {model_path}")
    
    def evaluate_models(self, X_test: np.ndarray, y_test: np.ndarray = None):
        """Evaluate trained models"""
        logger.info("="*60)
        logger.info("Evaluating Models")
        logger.info("="*60)
        
        # Evaluate anomaly detector
        anomaly_scores = self.anomaly_detector.score_samples(X_test)
        anomaly_predictions = self.anomaly_detector.predict(X_test)
        
        logger.info(f"Anomaly Detection:")
        logger.info(f"  Detected {anomaly_predictions.sum()} anomalies out of {len(X_test)} samples")
        logger.info(f"  Score range: [{anomaly_scores.min():.3f}, {anomaly_scores.max():.3f}]")
        
        # Evaluate classifier if labels available
        if y_test is not None and self.threat_classifier is not None:
            eval_results = self.threat_classifier.evaluate(X_test, y_test)
            
            logger.info(f"\nThreat Classification:")
            report = eval_results['classification_report']
            logger.info(f"  Overall Accuracy: {report['accuracy']:.4f}")
            logger.info(f"  Macro F1-Score: {report['macro avg']['f1-score']:.4f}")
            logger.info(f"  Weighted F1-Score: {report['weighted avg']['f1-score']:.4f}")
    
    def generate_report(self):
        """Generate training report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'config': self.config,
            'models': {
                'anomaly_detector': 'EnsembleAnomalyDetector',
                'threat_classifier': 'MultiClassThreatClassifier'
            },
            'status': 'completed'
        }
        
        report_path = f"logs/training_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
        with open(report_path, 'w') as f:
            yaml.dump(report, f, default_flow_style=False)
        
        logger.info(f"Training report saved to {report_path}")
    
    def run_full_pipeline(self, data_path: str, test_data_path: str = None):
        """Run complete training pipeline"""
        logger.info("="*60)
        logger.info("Starting Full Training Pipeline")
        logger.info("="*60)
        
        # Load training data
        df_train = self.load_data(data_path)
        
        # Prepare features
        X_train, y_train = self.prepare_features(df_train)
        
        # Save feature engineer state
        self.feature_engineer.save('data/models/feature_engineer.pkl')
        
        # Train models
        self.train_anomaly_detectors(X_train.values)
        
        if y_train is not None:
            self.train_threat_classifier(X_train.values, y_train.values)
        
        # Evaluate on test data if provided
        if test_data_path:
            df_test = self.load_data(test_data_path)
            X_test, y_test = self.prepare_features(df_test)
            self.evaluate_models(X_test.values, y_test.values if y_test is not None else None)
        
        # Generate report
        self.generate_report()
        
        logger.info("="*60)
        logger.info("Training Pipeline Completed Successfully!")
        logger.info("="*60)


def generate_synthetic_data(n_samples: int = 10000, output_path: str = 'data/raw/synthetic_data.parquet'):
    """Generate synthetic training data for testing"""
    logger.info(f"Generating {n_samples} synthetic samples...")
    
    np.random.seed(42)
    
    # Generate network features
    data = {
        'timestamp': pd.date_range('2024-01-01', periods=n_samples, freq='1min'),
        'connection_id': range(n_samples),
        'src_ip': [f"192.168.{np.random.randint(1,255)}.{np.random.randint(1,255)}" for _ in range(n_samples)],
        'dst_ip': [f"10.0.{np.random.randint(1,255)}.{np.random.randint(1,255)}" for _ in range(n_samples)],
        'src_port': np.random.randint(1024, 65535, n_samples),
        'dst_port': np.random.choice([80, 443, 22, 3389, 3306], n_samples),
        'protocol': np.random.choice([6, 17], n_samples),  # TCP, UDP
        'packets': np.random.randint(1, 1000, n_samples),
        'bytes': np.random.randint(100, 1000000, n_samples),
        'flow_duration': np.random.rand(n_samples) * 300,
    }
    
    # Generate labels (90% normal, 10% various attacks)
    labels = ['normal'] * int(n_samples * 0.9)
    attack_types = ['dos', 'port_scan', 'brute_force', 'malware', 'data_exfiltration']
    labels.extend(np.random.choice(attack_types, int(n_samples * 0.1)))
    np.random.shuffle(labels)
    data['label'] = labels
    
    df = pd.DataFrame(data)
    
    # Save to parquet
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output_path, compression='snappy')
    
    logger.info(f"Synthetic data saved to {output_path}")
    return df


def main():
    parser = argparse.ArgumentParser(description='Train ML Threat Detection Models')
    parser.add_argument('--config', default='config/config.yaml', help='Configuration file')
    parser.add_argument('--data', default='data/raw', help='Training data path')
    parser.add_argument('--test-data', default=None, help='Test data path (optional)')
    parser.add_argument('--generate-data', action='store_true', help='Generate synthetic data')
    
    args = parser.parse_args()
    
    # Create necessary directories
    Path('data/models').mkdir(parents=True, exist_ok=True)
    Path('logs').mkdir(parents=True, exist_ok=True)
    
    # Generate synthetic data if requested
    if args.generate_data:
        generate_synthetic_data(n_samples=10000, output_path='data/raw/synthetic_train.parquet')
        generate_synthetic_data(n_samples=2000, output_path='data/processed/synthetic_test.parquet')
        args.data = 'data/raw/synthetic_train.parquet'
        args.test_data = 'data/processed/synthetic_test.parquet'
    
    # Run training pipeline
    pipeline = TrainingPipeline(args.config)
    pipeline.run_full_pipeline(args.data, args.test_data)


if __name__ == "__main__":
    main()
