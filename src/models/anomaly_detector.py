"""
Anomaly Detection Models
Implements Isolation Forest, Autoencoder, LSTM, and ensemble methods
"""

import logging
from typing import Dict, Any, Optional, Tuple
import numpy as np
import pandas as pd
from pathlib import Path
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# TensorFlow is optional (not available on Python 3.14+)
try:
    from tensorflow import keras
    from tensorflow.keras import layers, models
    from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    keras = None
    layers = None
    models = None

logger = logging.getLogger(__name__)


class IsolationForestDetector:
    """Isolation Forest for outlier detection"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model = IsolationForest(
            n_estimators=config.get('n_estimators', 200),
            max_samples=config.get('max_samples', 256),
            contamination=config.get('contamination', 0.01),
            random_state=config.get('random_state', 42),
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        
    def fit(self, X: np.ndarray):
        """Train the Isolation Forest model"""
        logger.info(f"Training Isolation Forest on {X.shape[0]} samples")
        
        # Normalize data
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled)
        
        logger.info("Isolation Forest training complete")
        
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomalies (-1 for outliers, 1 for inliers)"""
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)
    
    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores (lower is more anomalous)"""
        X_scaled = self.scaler.transform(X)
        scores = self.model.score_samples(X_scaled)
        # Normalize to 0-1 range (higher is more anomalous)
        normalized_scores = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
        return normalized_scores
    
    def save(self, path: str):
        """Save model to disk"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'config': self.config
        }
        joblib.dump(model_data, path)
        logger.info(f"Model saved to {path}")
    
    def load(self, path: str):
        """Load model from disk"""
        model_data = joblib.load(path)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.config = model_data['config']
        logger.info(f"Model loaded from {path}")


class AutoencoderDetector:
    """Autoencoder for anomaly detection using reconstruction error"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.encoding_dim = config.get('encoding_dim', 32)
        self.hidden_layers = config.get('hidden_layers', [128, 64, 32])
        self.activation = config.get('activation', 'relu')
        self.epochs = config.get('epochs', 100)
        self.batch_size = config.get('batch_size', 256)
        
        self.model = None
        self.encoder = None
        self.scaler = StandardScaler()
        self.threshold = None
        
    def build_model(self, input_dim: int):
        """Build autoencoder architecture"""
        
        # Input layer
        input_layer = layers.Input(shape=(input_dim,))
        
        # Encoder
        encoded = input_layer
        for units in self.hidden_layers:
            encoded = layers.Dense(units, activation=self.activation)(encoded)
            encoded = layers.Dropout(0.2)(encoded)
        
        # Bottleneck
        encoded = layers.Dense(self.encoding_dim, activation=self.activation, name='encoding')(encoded)
        
        # Decoder (mirror of encoder)
        decoded = encoded
        for units in reversed(self.hidden_layers):
            decoded = layers.Dense(units, activation=self.activation)(decoded)
            decoded = layers.Dropout(0.2)(decoded)
        
        # Output layer
        decoded = layers.Dense(input_dim, activation='linear')(decoded)
        
        # Create models
        self.model = models.Model(input_layer, decoded)
        self.encoder = models.Model(input_layer, encoded)
        
        # Compile
        self.model.compile(
            optimizer='adam',
            loss='mse',
            metrics=['mae']
        )
        
        logger.info(f"Built autoencoder with input_dim={input_dim}, encoding_dim={self.encoding_dim}")
        
    def fit(self, X: np.ndarray, validation_split: float = 0.2):
        """Train the autoencoder"""
        logger.info(f"Training Autoencoder on {X.shape[0]} samples")
        
        # Build model if not already built
        if self.model is None:
            self.build_model(X.shape[1])
        
        # Normalize data
        X_scaled = self.scaler.fit_transform(X)
        
        # Callbacks
        callbacks = [
            EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True
            ),
            ModelCheckpoint(
                'data/models/autoencoder_checkpoint.h5',
                monitor='val_loss',
                save_best_only=True
            )
        ]
        
        # Train
        history = self.model.fit(
            X_scaled, X_scaled,
            epochs=self.epochs,
            batch_size=self.batch_size,
            validation_split=validation_split,
            callbacks=callbacks,
            verbose=1
        )
        
        # Calculate threshold using training data
        reconstruction_errors = self._calculate_reconstruction_error(X_scaled)
        self.threshold = np.percentile(reconstruction_errors, 95)  # 95th percentile
        
        logger.info(f"Training complete. Threshold: {self.threshold:.4f}")
        return history
    
    def _calculate_reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """Calculate reconstruction error"""
        reconstructed = self.model.predict(X, verbose=0)
        mse = np.mean(np.square(X - reconstructed), axis=1)
        return mse
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomalies based on reconstruction error"""
        X_scaled = self.scaler.transform(X)
        errors = self._calculate_reconstruction_error(X_scaled)
        return (errors > self.threshold).astype(int)
    
    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores (normalized reconstruction error)"""
        X_scaled = self.scaler.transform(X)
        errors = self._calculate_reconstruction_error(X_scaled)
        # Normalize to 0-1 range
        normalized_scores = errors / (self.threshold + 1e-8)
        return np.clip(normalized_scores, 0, 1)
    
    def get_encoding(self, X: np.ndarray) -> np.ndarray:
        """Get encoded representation"""
        X_scaled = self.scaler.transform(X)
        return self.encoder.predict(X_scaled, verbose=0)
    
    def save(self, path: str):
        """Save model to disk"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.model.save(f"{path}_model.h5")
        
        model_data = {
            'scaler': self.scaler,
            'config': self.config,
            'threshold': self.threshold
        }
        joblib.dump(model_data, f"{path}_data.pkl")
        logger.info(f"Model saved to {path}")
    
    def load(self, path: str):
        """Load model from disk"""
        self.model = keras.models.load_model(f"{path}_model.h5")
        
        # Rebuild encoder
        encoding_layer = self.model.get_layer('encoding')
        self.encoder = models.Model(
            self.model.input,
            encoding_layer.output
        )
        
        model_data = joblib.load(f"{path}_data.pkl")
        self.scaler = model_data['scaler']
        self.config = model_data['config']
        self.threshold = model_data['threshold']
        logger.info(f"Model loaded from {path}")


class LSTMDetector:
    """LSTM for sequence-based anomaly detection"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.units = config.get('units', 64)
        self.sequence_length = config.get('sequence_length', 50)
        self.dropout = config.get('dropout', 0.2)
        self.recurrent_dropout = config.get('recurrent_dropout', 0.2)
        self.epochs = config.get('epochs', 50)
        
        self.model = None
        self.scaler = StandardScaler()
        self.threshold = None
        
    def build_model(self, input_dim: int):
        """Build LSTM architecture"""
        
        model = models.Sequential([
            layers.LSTM(
                self.units,
                input_shape=(self.sequence_length, input_dim),
                dropout=self.dropout,
                recurrent_dropout=self.recurrent_dropout,
                return_sequences=True
            ),
            layers.LSTM(
                self.units // 2,
                dropout=self.dropout,
                recurrent_dropout=self.recurrent_dropout,
                return_sequences=False
            ),
            layers.Dense(self.units // 4, activation='relu'),
            layers.Dropout(0.3),
            layers.Dense(input_dim, activation='linear')
        ])
        
        model.compile(
            optimizer='adam',
            loss='mse',
            metrics=['mae']
        )
        
        self.model = model
        logger.info(f"Built LSTM with sequence_length={self.sequence_length}")
        
    def _create_sequences(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Create sequences for LSTM"""
        sequences = []
        targets = []
        
        for i in range(len(X) - self.sequence_length):
            sequences.append(X[i:i + self.sequence_length])
            targets.append(X[i + self.sequence_length])
        
        return np.array(sequences), np.array(targets)
    
    def fit(self, X: np.ndarray, validation_split: float = 0.2):
        """Train the LSTM model"""
        logger.info(f"Training LSTM on {X.shape[0]} samples")
        
        # Build model if not already built
        if self.model is None:
            self.build_model(X.shape[1])
        
        # Normalize data
        X_scaled = self.scaler.fit_transform(X)
        
        # Create sequences
        X_seq, y_seq = self._create_sequences(X_scaled)
        
        # Callbacks
        callbacks = [
            EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True
            )
        ]
        
        # Train
        history = self.model.fit(
            X_seq, y_seq,
            epochs=self.epochs,
            batch_size=256,
            validation_split=validation_split,
            callbacks=callbacks,
            verbose=1
        )
        
        # Calculate threshold
        predictions = self.model.predict(X_seq, verbose=0)
        errors = np.mean(np.square(y_seq - predictions), axis=1)
        self.threshold = np.percentile(errors, 95)
        
        logger.info(f"Training complete. Threshold: {self.threshold:.4f}")
        return history
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomalies in sequences"""
        X_scaled = self.scaler.transform(X)
        X_seq, y_seq = self._create_sequences(X_scaled)
        
        predictions = self.model.predict(X_seq, verbose=0)
        errors = np.mean(np.square(y_seq - predictions), axis=1)
        
        return (errors > self.threshold).astype(int)
    
    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores for sequences"""
        X_scaled = self.scaler.transform(X)
        X_seq, y_seq = self._create_sequences(X_scaled)
        
        predictions = self.model.predict(X_seq, verbose=0)
        errors = np.mean(np.square(y_seq - predictions), axis=1)
        
        # Normalize
        normalized_scores = errors / (self.threshold + 1e-8)
        return np.clip(normalized_scores, 0, 1)
    
    def save(self, path: str):
        """Save model to disk"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.model.save(f"{path}_model.h5")
        
        model_data = {
            'scaler': self.scaler,
            'config': self.config,
            'threshold': self.threshold
        }
        joblib.dump(model_data, f"{path}_data.pkl")
        logger.info(f"Model saved to {path}")
    
    def load(self, path: str):
        """Load model from disk"""
        self.model = keras.models.load_model(f"{path}_model.h5")
        
        model_data = joblib.load(f"{path}_data.pkl")
        self.scaler = model_data['scaler']
        self.config = model_data['config']
        self.threshold = model_data['threshold']
        logger.info(f"Model loaded from {path}")


class EnsembleAnomalyDetector:
    """Ensemble of multiple anomaly detectors"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.detectors = {}
        
        # Initialize individual detectors
        if 'isolation_forest' in config:
            self.detectors['isolation_forest'] = IsolationForestDetector(
                config['isolation_forest']
            )
        
        if 'autoencoder' in config and TENSORFLOW_AVAILABLE:
            self.detectors['autoencoder'] = AutoencoderDetector(
                config['autoencoder']
            )
        
        if 'lstm' in config and TENSORFLOW_AVAILABLE:
            self.detectors['lstm'] = LSTMDetector(
                config['lstm']
            )
    
    def fit(self, X: np.ndarray):
        """Train all detectors"""
        logger.info(f"Training ensemble of {len(self.detectors)} detectors")
        
        for name, detector in self.detectors.items():
            logger.info(f"Training {name}...")
            detector.fit(X)
    
    def predict(self, X: np.ndarray, voting: str = 'soft') -> np.ndarray:
        """Ensemble prediction"""
        if voting == 'hard':
            # Majority voting
            predictions = np.array([
                detector.predict(X) for detector in self.detectors.values()
            ])
            return (predictions.sum(axis=0) > len(self.detectors) / 2).astype(int)
        else:
            # Soft voting using scores
            scores = self.score_samples(X)
            threshold = self.config.get('ensemble_threshold', 0.7)
            return (scores > threshold).astype(int)
    
    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Get ensemble anomaly scores"""
        scores = np.array([
            detector.score_samples(X) for detector in self.detectors.values()
        ])
        # Average scores
        return scores.mean(axis=0)
    
    def save(self, path: str):
        """Save all detectors"""
        Path(path).mkdir(parents=True, exist_ok=True)
        
        for name, detector in self.detectors.items():
            detector.save(f"{path}/{name}")
        
        logger.info(f"Ensemble saved to {path}")
    
    def load(self, path: str):
        """Load all detectors"""
        for name, detector in self.detectors.items():
            detector.load(f"{path}/{name}")
        
        logger.info(f"Ensemble loaded from {path}")


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Generate sample data
    np.random.seed(42)
    normal_data = np.random.randn(1000, 20)
    anomalies = np.random.randn(50, 20) * 3
    X_train = normal_data
    X_test = np.vstack([normal_data[:100], anomalies])
    
    # Test Isolation Forest
    config = {
        'isolation_forest': {
            'n_estimators': 100,
            'contamination': 0.05
        }
    }
    
    detector = IsolationForestDetector(config['isolation_forest'])
    detector.fit(X_train)
    predictions = detector.predict(X_test)
    scores = detector.score_samples(X_test)
    
    print(f"Detected {predictions.sum()} anomalies out of {len(X_test)} samples")
    print(f"Anomaly scores range: [{scores.min():.3f}, {scores.max():.3f}]")
