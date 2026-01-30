"""
K-Means Clustering-Based Anomaly Detection
Uses distance from cluster centers to identify anomalies
"""

import logging
from typing import Dict, Any, Optional
import numpy as np
import pandas as pd
from pathlib import Path
import joblib

from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
from scipy.spatial.distance import mahalanobis

logger = logging.getLogger(__name__)


class KMeansAnomalyDetector:
    """
    K-Means Clustering for Anomaly Detection
    
    Normal traffic is clustered into K groups. Anomalies are detected as
    data points that are far from all cluster centers.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize K-Means detector
        
        Args:
            config: Configuration dictionary with parameters:
                - n_clusters: Number of clusters (default: 10)
                - max_iter: Maximum iterations for K-Means (default: 300)
                - contamination: Expected proportion of anomalies (default: 0.1)
                - distance_metric: 'euclidean' or 'mahalanobis' (default: 'euclidean')
        """
        self.config = config
        self.n_clusters = config.get('n_clusters', 10)
        self.max_iter = config.get('max_iter', 300)
        self.contamination = config.get('contamination', 0.1)
        self.distance_metric = config.get('distance_metric', 'euclidean')
        
        # Initialize K-Means
        self.model = KMeans(
            n_clusters=self.n_clusters,
            max_iter=self.max_iter,
            random_state=config.get('random_state', 42),
            n_init=10,
            algorithm='lloyd'
        )
        
        self.scaler = StandardScaler()
        self.threshold = None
        self.cluster_covariances = None  # For Mahalanobis distance
        
    def fit(self, X: np.ndarray):
        """
        Train the K-Means model on normal traffic data
        
        Args:
            X: Training data (should be mostly normal traffic)
        """
        logger.info(f"Training K-Means with {self.n_clusters} clusters on {X.shape[0]} samples")
        
        # Normalize data
        X_scaled = self.scaler.fit_transform(X)
        
        # Fit K-Means
        self.model.fit(X_scaled)
        
        # Calculate silhouette score for quality assessment
        try:
            silhouette_avg = silhouette_score(X_scaled, self.model.labels_)
            logger.info(f"Silhouette Score: {silhouette_avg:.4f}")
        except Exception as e:
            logger.warning(f"Could not calculate silhouette score: {e}")
        
        # Calculate cluster covariances for Mahalanobis distance
        if self.distance_metric == 'mahalanobis':
            self._calculate_cluster_covariances(X_scaled)
        
        # Calculate distances for all training samples
        distances = self._calculate_distances(X_scaled)
        
        # Set threshold based on contamination parameter
        # Threshold is set at the percentile corresponding to contamination
        threshold_percentile = (1 - self.contamination) * 100
        self.threshold = np.percentile(distances, threshold_percentile)
        
        logger.info(f"K-Means training complete. Threshold: {self.threshold:.4f}")
        logger.info(f"Cluster centers shape: {self.model.cluster_centers_.shape}")
        
    def _calculate_cluster_covariances(self, X_scaled: np.ndarray):
        """Calculate covariance matrix for each cluster (for Mahalanobis distance)"""
        self.cluster_covariances = []
        
        for i in range(self.n_clusters):
            # Get points in this cluster
            cluster_points = X_scaled[self.model.labels_ == i]
            
            if len(cluster_points) > 1:
                # Calculate covariance matrix
                cov = np.cov(cluster_points.T)
                # Add small regularization to ensure invertibility
                cov += np.eye(cov.shape[0]) * 1e-6
                self.cluster_covariances.append(cov)
            else:
                # Use identity matrix if cluster has too few points
                self.cluster_covariances.append(np.eye(X_scaled.shape[1]))
    
    def _calculate_distances(self, X_scaled: np.ndarray) -> np.ndarray:
        """
        Calculate distance from each point to its nearest cluster center
        
        Args:
            X_scaled: Normalized feature matrix
            
        Returns:
            Array of distances to nearest cluster
        """
        if self.distance_metric == 'euclidean':
            # Euclidean distance to all cluster centers
            distances_to_centers = self.model.transform(X_scaled)
            # Minimum distance to any cluster
            min_distances = np.min(distances_to_centers, axis=1)
            
        elif self.distance_metric == 'mahalanobis':
            min_distances = []
            
            for i, point in enumerate(X_scaled):
                min_dist = float('inf')
                
                for j, center in enumerate(self.model.cluster_centers_):
                    try:
                        # Calculate Mahalanobis distance to this cluster
                        diff = point - center
                        cov_inv = np.linalg.inv(self.cluster_covariances[j])
                        dist = np.sqrt(diff.T @ cov_inv @ diff)
                        min_dist = min(min_dist, dist)
                    except:
                        # Fall back to Euclidean if covariance is singular
                        dist = np.linalg.norm(point - center)
                        min_dist = min(min_dist, dist)
                
                min_distances.append(min_dist)
            
            min_distances = np.array(min_distances)
        else:
            raise ValueError(f"Unknown distance metric: {self.distance_metric}")
        
        return min_distances
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomalies (1 for anomaly, -1 for normal)
        
        Args:
            X: Data to predict
            
        Returns:
            Array of predictions (-1 for anomaly, 1 for normal)
        """
        X_scaled = self.scaler.transform(X)
        distances = self._calculate_distances(X_scaled)
        
        # Points beyond threshold are anomalies
        # Return -1 for anomalies (consistent with IsolationForest)
        predictions = np.where(distances > self.threshold, -1, 1)
        return predictions
    
    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Get anomaly scores (0-1 range, higher means more anomalous)
        
        Args:
            X: Data to score
            
        Returns:
            Array of anomaly scores
        """
        X_scaled = self.scaler.transform(X)
        distances = self._calculate_distances(X_scaled)
        
        # Normalize distances to 0-1 range
        # Use threshold as reference point
        normalized_scores = distances / (self.threshold + 1e-8)
        
        # Clip to [0, 1] range
        normalized_scores = np.clip(normalized_scores, 0, 1)
        
        return normalized_scores
    
    def get_cluster_info(self, X: np.ndarray) -> Dict[str, Any]:
        """
        Get detailed cluster information for data points
        
        Args:
            X: Data to analyze
            
        Returns:
            Dictionary with cluster assignments and distances
        """
        X_scaled = self.scaler.transform(X)
        
        # Get cluster assignments
        cluster_labels = self.model.predict(X_scaled)
        
        # Get distances to all clusters
        distances_to_all = self.model.transform(X_scaled)
        
        # Get distances to nearest cluster
        min_distances = self._calculate_distances(X_scaled)
        
        return {
            'cluster_labels': cluster_labels,
            'distances_to_nearest': min_distances,
            'distances_to_all_centers': distances_to_all,
            'n_clusters': self.n_clusters,
            'threshold': self.threshold
        }
    
    def save(self, path: str):
        """Save model to disk"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'config': self.config,
            'threshold': self.threshold,
            'cluster_covariances': self.cluster_covariances
        }
        joblib.dump(model_data, path)
        logger.info(f"K-Means model saved to {path}")
    
    def load(self, path: str):
        """Load model from disk"""
        model_data = joblib.load(path)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.config = model_data['config']
        self.threshold = model_data['threshold']
        self.cluster_covariances = model_data.get('cluster_covariances')
        
        # Update config parameters
        self.n_clusters = self.config.get('n_clusters', 10)
        self.contamination = self.config.get('contamination', 0.1)
        self.distance_metric = self.config.get('distance_metric', 'euclidean')
        
        logger.info(f"K-Means model loaded from {path}")


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.INFO)
    
    # Generate sample data
    np.random.seed(42)
    
    # Normal data (3 natural clusters)
    normal_cluster1 = np.random.randn(300, 10) + np.array([0] * 10)
    normal_cluster2 = np.random.randn(300, 10) + np.array([5] * 10)
    normal_cluster3 = np.random.randn(300, 10) + np.array([-5] * 10)
    normal_data = np.vstack([normal_cluster1, normal_cluster2, normal_cluster3])
    
    # Anomalies (far from normal clusters)
    anomalies = np.random.randn(50, 10) * 5 + np.array([15] * 10)
    
    # Test data
    X_train = normal_data
    X_test = np.vstack([normal_data[:100], anomalies])
    
    # Test with Euclidean distance
    print("\n=== Testing K-Means with Euclidean Distance ===")
    config_euclidean = {
        'n_clusters': 5,
        'contamination': 0.1,
        'distance_metric': 'euclidean'
    }
    
    detector_euclidean = KMeansAnomalyDetector(config_euclidean)
    detector_euclidean.fit(X_train)
    
    predictions = detector_euclidean.predict(X_test)
    scores = detector_euclidean.score_samples(X_test)
    
    n_anomalies = np.sum(predictions == -1)
    print(f"Detected {n_anomalies} anomalies out of {len(X_test)} samples")
    print(f"Anomaly scores range: [{scores.min():.3f}, {scores.max():.3f}]")
    
    # Test with Mahalanobis distance
    print("\n=== Testing K-Means with Mahalanobis Distance ===")
    config_mahalanobis = {
        'n_clusters': 5,
        'contamination': 0.1,
        'distance_metric': 'mahalanobis'
    }
    
    detector_mahalanobis = KMeansAnomalyDetector(config_mahalanobis)
    detector_mahalanobis.fit(X_train)
    
    predictions_maha = detector_mahalanobis.predict(X_test)
    scores_maha = detector_mahalanobis.score_samples(X_test)
    
    n_anomalies_maha = np.sum(predictions_maha == -1)
    print(f"Detected {n_anomalies_maha} anomalies out of {len(X_test)} samples")
    print(f"Anomaly scores range: [{scores_maha.min():.3f}, {scores_maha.max():.3f}]")
    
    # Test save/load
    print("\n=== Testing Save/Load ===")
    detector_euclidean.save("test_kmeans_model.pkl")
    
    detector_loaded = KMeansAnomalyDetector({})
    detector_loaded.load("test_kmeans_model.pkl")
    
    predictions_loaded = detector_loaded.predict(X_test)
    print(f"Loaded model predictions match: {np.array_equal(predictions, predictions_loaded)}")
    
    # Get cluster info
    print("\n=== Cluster Information ===")
    cluster_info = detector_euclidean.get_cluster_info(X_test[:10])
    print(f"Cluster labels for first 10 samples: {cluster_info['cluster_labels']}")
    print(f"Distances to nearest cluster: {cluster_info['distances_to_nearest'][:5]}")
