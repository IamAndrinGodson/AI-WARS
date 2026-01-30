"""
Threat Classification Module
Multi-class classification for known attack types
"""

import logging
from typing import Dict, Any, List
import numpy as np
import pandas as pd
from pathlib import Path
import joblib

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import xgboost as xgb
import lightgbm as lgb

logger = logging.getLogger(__name__)


class ThreatClassifier:
    """Multi-class threat classification system"""
    
    # Threat categories
    THREAT_CLASSES = [
        'normal',
        'dos',  # Denial of Service
        'ddos',  # Distributed DoS
        'port_scan',  # Reconnaissance
        'brute_force',  # Authentication attacks
        'sql_injection',  # Code injection
        'xss',  # Cross-site scripting
        'malware',  # Malware infection
        'data_exfiltration',  # Data theft
        'lateral_movement',  # Internal propagation
        'privilege_escalation',  # Permission abuse
        'ransomware',  # Encryption attacks
        'phishing',  # Social engineering
        'botnet',  # Command and control
        'zero_day'  # Unknown threats
    ]
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.models = {}
        self.label_encoder = LabelEncoder()
        self.label_encoder.fit(self.THREAT_CLASSES)
        
        self._initialize_models()
        
    def _initialize_models(self):
        """Initialize all classification models"""
        
        # XGBoost
        if 'xgboost' in self.config:
            xgb_config = self.config['xgboost']
            self.models['xgboost'] = xgb.XGBClassifier(
                max_depth=xgb_config.get('max_depth', 7),
                learning_rate=xgb_config.get('learning_rate', 0.1),
                n_estimators=xgb_config.get('n_estimators', 200),
                objective='multi:softmax',
                num_class=len(self.THREAT_CLASSES),
                tree_method='hist',
                random_state=42
            )
        
        # LightGBM
        if 'lightgbm' in self.config:
            lgb_config = self.config['lightgbm']
            self.models['lightgbm'] = lgb.LGBMClassifier(
                num_leaves=lgb_config.get('num_leaves', 31),
                learning_rate=lgb_config.get('learning_rate', 0.05),
                n_estimators=lgb_config.get('n_estimators', 200),
                objective='multiclass',
                num_class=len(self.THREAT_CLASSES),
                random_state=42
            )
        
        # Random Forest
        self.models['random_forest'] = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        )
        
        # Gradient Boosting
        self.models['gradient_boosting'] = GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=7,
            random_state=42
        )
        
        logger.info(f"Initialized {len(self.models)} classification models")
    
    def fit(self, X: np.ndarray, y: np.ndarray, validation_split: float = 0.2):
        """Train all models"""
        logger.info(f"Training classifiers on {X.shape[0]} samples")
        
        # Fit encoder on actual labels (not predefined classes)
        self.label_encoder.fit(y)
        y_encoded = self.label_encoder.transform(y)
        
        # Update num_class for XGBoost/LightGBM if needed
        n_classes = len(self.label_encoder.classes_)
        if 'xgboost' in self.models:
            self.models['xgboost'].set_params(num_class=n_classes)
        if 'lightgbm' in self.models:
            self.models['lightgbm'].set_params(num_class=n_classes)
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X, y_encoded,
            test_size=validation_split,
            stratify=y_encoded,
            random_state=42
        )
        
        # Train each model
        results = {}
        for name, model in self.models.items():
            logger.info(f"Training {name}...")
            
            model.fit(X_train, y_train)
            
            # Evaluate
            train_score = model.score(X_train, y_train)
            val_score = model.score(X_val, y_val)
            
            results[name] = {
                'train_score': train_score,
                'val_score': val_score
            }
            
            logger.info(f"{name} - Train: {train_score:.4f}, Val: {val_score:.4f}")
        
        # Cross-validation scores
        logger.info("Performing cross-validation...")
        for name, model in self.models.items():
            cv_scores = cross_val_score(model, X_train, y_train, cv=5)
            results[name]['cv_mean'] = cv_scores.mean()
            results[name]['cv_std'] = cv_scores.std()
            logger.info(f"{name} CV: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        
        return results
    
    def predict(self, X: np.ndarray, model_name: str = 'ensemble') -> np.ndarray:
        """Predict threat classes"""
        if model_name == 'ensemble':
            return self._ensemble_predict(X)
        elif model_name in self.models:
            predictions = self.models[model_name].predict(X)
            return self.label_encoder.inverse_transform(predictions)
        else:
            raise ValueError(f"Unknown model: {model_name}")
    
    def predict_proba(self, X: np.ndarray, model_name: str = 'ensemble') -> np.ndarray:
        """Predict class probabilities"""
        if model_name == 'ensemble':
            return self._ensemble_predict_proba(X)
        elif model_name in self.models:
            return self.models[model_name].predict_proba(X)
        else:
            raise ValueError(f"Unknown model: {model_name}")
    
    def _ensemble_predict(self, X: np.ndarray, voting: str = 'soft') -> np.ndarray:
        """Ensemble prediction using multiple models"""
        if voting == 'hard':
            # Majority voting
            predictions = []
            for model in self.models.values():
                pred = model.predict(X)
                predictions.append(pred)
            
            predictions = np.array(predictions)
            final_pred = np.apply_along_axis(
                lambda x: np.bincount(x).argmax(),
                axis=0,
                arr=predictions
            )
        else:
            # Soft voting using probabilities
            probas = self._ensemble_predict_proba(X)
            final_pred = np.argmax(probas, axis=1)
        
        return self.label_encoder.inverse_transform(final_pred)
    
    def _ensemble_predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Ensemble probability prediction"""
        all_probas = []
        
        for model in self.models.values():
            proba = model.predict_proba(X)
            all_probas.append(proba)
        
        # Average probabilities
        ensemble_proba = np.mean(all_probas, axis=0)
        return ensemble_proba
    
    def get_feature_importance(self, model_name: str = 'xgboost') -> pd.DataFrame:
        """Get feature importance from a model"""
        if model_name not in self.models:
            raise ValueError(f"Unknown model: {model_name}")
        
        model = self.models[model_name]
        
        if hasattr(model, 'feature_importances_'):
            importance = model.feature_importances_
            return pd.DataFrame({
                'feature_idx': range(len(importance)),
                'importance': importance
            }).sort_values('importance', ascending=False)
        else:
            logger.warning(f"Model {model_name} doesn't support feature importance")
            return pd.DataFrame()
    
    def evaluate(self, X: np.ndarray, y: np.ndarray, model_name: str = 'ensemble'):
        """Evaluate model performance"""
        y_encoded = self.label_encoder.transform(y)
        
        if model_name == 'ensemble':
            y_pred = self._ensemble_predict(X)
            y_pred_encoded = self.label_encoder.transform(y_pred)
        else:
            y_pred_encoded = self.models[model_name].predict(X)
            y_pred = self.label_encoder.inverse_transform(y_pred_encoded)
        
        # Classification report
        report = classification_report(
            y,
            y_pred,
            target_names=list(self.label_encoder.classes_),
            output_dict=True
        )
        
        # Confusion matrix
        cm = confusion_matrix(y_encoded, y_pred_encoded)
        
        return {
            'classification_report': report,
            'confusion_matrix': cm,
            'predictions': y_pred
        }
    
    def save(self, path: str):
        """Save all models"""
        Path(path).mkdir(parents=True, exist_ok=True)
        
        # Save each model
        for name, model in self.models.items():
            joblib.dump(model, f"{path}/{name}.pkl")
        
        # Save label encoder and config
        metadata = {
            'label_encoder': self.label_encoder,
            'config': self.config,
            'threat_classes': self.THREAT_CLASSES
        }
        joblib.dump(metadata, f"{path}/metadata.pkl")
        
        logger.info(f"Models saved to {path}")
    
    def load(self, path: str):
        """Load all models"""
        # Load metadata
        metadata = joblib.load(f"{path}/metadata.pkl")
        self.label_encoder = metadata['label_encoder']
        self.config = metadata['config']
        
        # Load each model
        for name in self.models.keys():
            model_path = f"{path}/{name}.pkl"
            if Path(model_path).exists():
                self.models[name] = joblib.load(model_path)
        
        logger.info(f"Models loaded from {path}")


class ZeroDayDetector:
    """Specialized detector for zero-day threats"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.behavior_divergence_threshold = config.get('behavior_divergence_threshold', 0.9)
        self.min_correlation_events = config.get('min_correlation_events', 3)
        
    def detect(
        self,
        features: np.ndarray,
        anomaly_score: float,
        normal_baseline: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Detect potential zero-day threats"""
        
        # Calculate behavior divergence
        divergence_score = self._calculate_divergence(features, normal_baseline)
        
        # Correlate multiple signals
        is_zero_day = (
            divergence_score > self.behavior_divergence_threshold and
            anomaly_score > 0.8
        )
        
        return {
            'is_zero_day': is_zero_day,
            'divergence_score': divergence_score,
            'confidence': (divergence_score + anomaly_score) / 2,
            'indicators': self._extract_indicators(features, normal_baseline)
        }
    
    def _calculate_divergence(
        self,
        features: np.ndarray,
        baseline: Dict[str, Any]
    ) -> float:
        """Calculate statistical divergence from baseline"""
        # Simplified implementation - would use KL divergence, Wasserstein distance, etc.
        if 'mean' not in baseline or 'std' not in baseline:
            return 0.0
        
        z_scores = np.abs((features - baseline['mean']) / (baseline['std'] + 1e-8))
        max_divergence = np.max(z_scores)
        
        # Normalize to 0-1
        return min(max_divergence / 5.0, 1.0)
    
    def _extract_indicators(
        self,
        features: np.ndarray,
        baseline: Dict[str, Any]
    ) -> List[str]:
        """Extract specific indicators of compromise"""
        indicators = []
        
        # Check for unusual patterns
        if 'mean' in baseline:
            z_scores = (features - baseline['mean']) / (baseline['std'] + 1e-8)
            
            if np.any(z_scores > 3):
                indicators.append("extreme_statistical_outlier")
            
            if np.any(z_scores < -3):
                indicators.append("unusual_low_values")
        
        return indicators


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Generate sample data
    np.random.seed(42)
    n_samples = 1000
    n_features = 20
    
    X = np.random.randn(n_samples, n_features)
    y = np.random.choice(
        ThreatClassifier.THREAT_CLASSES[:5],  # Use subset for demo
        size=n_samples
    )
    
    # Train classifier
    config = {
        'xgboost': {
            'max_depth': 7,
            'learning_rate': 0.1,
            'n_estimators': 100
        },
        'lightgbm': {
            'num_leaves': 31,
            'learning_rate': 0.05,
            'n_estimators': 100
        }
    }
    
    classifier = ThreatClassifier(config)
    results = classifier.fit(X, y)
    
    # Make predictions
    predictions = classifier.predict(X[:10])
    probas = classifier.predict_proba(X[:10])
    
    print(f"Predictions: {predictions}")
    print(f"Probabilities shape: {probas.shape}")
    
    # Feature importance
    importance = classifier.get_feature_importance()
    print(f"\nTop 5 important features:\n{importance.head()}")
