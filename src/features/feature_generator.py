"""
Feature Engineering Module
Extracts and transforms features from raw security data
"""

import logging
from typing import Dict, List, Any
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from scipy.stats import entropy
from sklearn.preprocessing import StandardScaler, LabelEncoder

logger = logging.getLogger(__name__)


class FeatureEngineer:
    """Main feature engineering class"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.scaler = StandardScaler()
        self.encoders = {}
        
    def save(self, path: str):
        """Save feature engineer state"""
        import joblib
        from pathlib import Path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        
        state = {
            'scaler': self.scaler,
            'encoders': self.encoders,
            'config': self.config
        }
        joblib.dump(state, path)
        logger.info(f"Feature engineer state saved to {path}")
        
    def load(self, path: str):
        """Load feature engineer state"""
        import joblib
        from pathlib import Path
        
        if not Path(path).exists():
            logger.warning(f"Feature engineer state not found at {path}")
            return
            
        state = joblib.load(path)
        self.scaler = state['scaler']
        self.encoders = state['encoders']
        self.config = state['config']
        logger.info(f"Feature engineer state loaded from {path}")
        
    def extract_all_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract all configured features from raw data"""
        logger.info(f"Extracting features from {len(df)} records")
        
        feature_df = pd.DataFrame()
        
        # Network features
        if 'network' in self.config.get('features', {}):
            network_features = self.extract_network_features(df)
            feature_df = pd.concat([feature_df, network_features], axis=1)
        
        # User behavior features
        if 'user_behavior' in self.config.get('features', {}):
            user_features = self.extract_user_behavior_features(df)
            feature_df = pd.concat([feature_df, user_features], axis=1)
        
        # Temporal features
        if 'temporal' in self.config.get('features', {}):
            temporal_features = self.extract_temporal_features(df)
            feature_df = pd.concat([feature_df, temporal_features], axis=1)
        
        # Contextual features
        if 'contextual' in self.config.get('features', {}):
            contextual_features = self.extract_contextual_features(df)
            feature_df = pd.concat([feature_df, contextual_features], axis=1)
        
        # Fill NaN values
        feature_df = feature_df.fillna(0)
        
        logger.info(f"Extracted {feature_df.shape[1]} features")
        return feature_df
    
    def extract_network_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract network-level features"""
        features = pd.DataFrame()
        
        try:
            # Basic traffic statistics
            features['packet_count'] = df.groupby('connection_id')['packets'].sum()
            features['byte_count'] = df.groupby('connection_id')['bytes'].sum()
            features['duration'] = df.groupby('connection_id')['flow_duration'].sum()
            
            # Rate calculations
            features['packets_per_second'] = features['packet_count'] / (features['duration'] + 1e-6)
            features['bytes_per_second'] = features['byte_count'] / (features['duration'] + 1e-6)
            features['avg_packet_size'] = features['byte_count'] / (features['packet_count'] + 1e-6)
            
            # Protocol distribution
            protocol_dist = df.groupby('connection_id')['protocol'].value_counts(normalize=True)
            features['protocol_entropy'] = protocol_dist.groupby(level=0).apply(entropy)
            
            # Port entropy (measure of scanning behavior)
            if 'dst_port' in df.columns:
                port_dist = df.groupby('connection_id')['dst_port'].value_counts(normalize=True)
                features['port_entropy'] = port_dist.groupby(level=0).apply(entropy)
            
            # Connection patterns
            features['unique_dst_ips'] = df.groupby('connection_id')['dst_ip'].nunique()
            features['unique_dst_ports'] = df.groupby('connection_id')['dst_port'].nunique()
            
            # Packet size variance (detects tunneling, covert channels)
            features['packet_size_variance'] = df.groupby('connection_id')['bytes'].var()
            features['packet_size_std'] = df.groupby('connection_id')['bytes'].std()
            
            # Bidirectional flow metrics
            if 'direction' in df.columns:
                features['flow_asymmetry'] = self._calculate_flow_asymmetry(df)
            
        except Exception as e:
            logger.error(f"Error extracting network features: {e}")
        
        return features.fillna(0)
    
    def extract_user_behavior_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract user behavior analytics (UEBA) features"""
        features = pd.DataFrame()
        
        try:
            if 'user_id' not in df.columns:
                return features
            
            # Login frequency analysis
            features['login_frequency'] = df.groupby('user_id')['timestamp'].apply(
                lambda x: len(x) / ((x.max() - x.min()).total_seconds() / 3600 + 1)
            )
            
            # Access patterns
            features['unique_resources_accessed'] = df.groupby('user_id')['resource'].nunique()
            features['resource_access_entropy'] = df.groupby('user_id')['resource'].apply(
                lambda x: entropy(x.value_counts(normalize=True))
            )
            
            # Data movement patterns
            if 'data_volume' in df.columns:
                features['total_data_transfer'] = df.groupby('user_id')['data_volume'].sum()
                features['avg_data_transfer'] = df.groupby('user_id')['data_volume'].mean()
                features['max_data_transfer'] = df.groupby('user_id')['data_volume'].max()
            
            # Time-based anomalies
            features['unusual_time_access'] = self._detect_unusual_access_times(df)
            
            # Geographic anomalies
            if 'geolocation' in df.columns:
                features['location_changes'] = df.groupby('user_id')['geolocation'].nunique()
                features['impossible_travel'] = self._detect_impossible_travel(df)
            
        except Exception as e:
            logger.error(f"Error extracting user behavior features: {e}")
        
        return features.fillna(0)
    
    def extract_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract time-based features"""
        features = pd.DataFrame()
        
        try:
            # Convert timestamp to datetime
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Extract time components
            features['hour_of_day'] = df['timestamp'].dt.hour
            features['day_of_week'] = df['timestamp'].dt.dayofweek
            features['day_of_month'] = df['timestamp'].dt.day
            features['is_weekend'] = df['timestamp'].dt.dayofweek.isin([5, 6]).astype(int)
            features['is_business_hours'] = df['timestamp'].dt.hour.between(9, 17).astype(int)
            
            # Cyclical encoding for time features
            features['hour_sin'] = np.sin(2 * np.pi * features['hour_of_day'] / 24)
            features['hour_cos'] = np.cos(2 * np.pi * features['hour_of_day'] / 24)
            features['day_sin'] = np.sin(2 * np.pi * features['day_of_week'] / 7)
            features['day_cos'] = np.cos(2 * np.pi * features['day_of_week'] / 7)
            
            # Time since last event (for sequence analysis)
            features['time_since_last_event'] = df.groupby('user_id')['timestamp'].diff().dt.total_seconds()
            
            # Event frequency in time windows
            features['events_last_hour'] = self._count_events_in_window(df, hours=1)
            features['events_last_day'] = self._count_events_in_window(df, hours=24)
            
        except Exception as e:
            logger.error(f"Error extracting temporal features: {e}")
        
        return features.fillna(0)
    
    def extract_contextual_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract contextual features"""
        features = pd.DataFrame()
        
        try:
            # Geolocation features
            if 'geolocation' in df.columns:
                # Encode geographic locations
                if 'geolocation' not in self.encoders:
                    self.encoders['geolocation'] = LabelEncoder()
                    features['geo_encoded'] = self.encoders['geolocation'].fit_transform(df['geolocation'])
                else:
                    features['geo_encoded'] = self.encoders['geolocation'].transform(df['geolocation'])
            
            # Device fingerprinting
            if 'device_id' in df.columns:
                features['unique_devices'] = df.groupby('user_id')['device_id'].nunique()
                features['device_consistency'] = self._calculate_device_consistency(df)
            
            # Asset criticality
            if 'asset_id' in df.columns:
                features['asset_criticality'] = df['asset_id'].map(
                    self._get_asset_criticality_map()
                )
            
            # Business context
            if 'department' in df.columns:
                if 'department' not in self.encoders:
                    self.encoders['department'] = LabelEncoder()
                    features['department_encoded'] = self.encoders['department'].fit_transform(df['department'])
                else:
                    features['department_encoded'] = self.encoders['department'].transform(df['department'])
            
        except Exception as e:
            logger.error(f"Error extracting contextual features: {e}")
        
        return features.fillna(0)
    
    def _calculate_flow_asymmetry(self, df: pd.DataFrame) -> pd.Series:
        """Calculate bidirectional flow asymmetry"""
        forward = df[df['direction'] == 'forward'].groupby('connection_id')['bytes'].sum()
        backward = df[df['direction'] == 'backward'].groupby('connection_id')['bytes'].sum()
        return abs(forward - backward) / (forward + backward + 1e-6)
    
    def _detect_unusual_access_times(self, df: pd.DataFrame) -> pd.Series:
        """Detect unusual access times for users"""
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        
        # Calculate each user's normal access hours
        normal_hours = df.groupby('user_id')['hour'].apply(
            lambda x: set(x.mode().values)
        )
        
        # Flag access outside normal hours
        def is_unusual(row):
            if row['user_id'] in normal_hours:
                return 1 if row['hour'] not in normal_hours[row['user_id']] else 0
            return 0
        
        return df.apply(is_unusual, axis=1)
    
    def _detect_impossible_travel(self, df: pd.DataFrame) -> pd.Series:
        """Detect impossible travel scenarios"""
        # Simplified implementation
        df = df.sort_values(['user_id', 'timestamp'])
        df['prev_location'] = df.groupby('user_id')['geolocation'].shift(1)
        df['time_diff'] = df.groupby('user_id')['timestamp'].diff().dt.total_seconds()
        
        # Flag if location changed in < 1 hour
        impossible = (
            (df['geolocation'] != df['prev_location']) & 
            (df['time_diff'] < 3600)
        ).astype(int)
        
        return impossible
    
    def _count_events_in_window(self, df: pd.DataFrame, hours: int) -> pd.Series:
        """Count events in a time window"""
        df = df.sort_values('timestamp')
        window = pd.Timedelta(hours=hours)
        
        return df.groupby('user_id')['timestamp'].apply(
            lambda x: x.rolling(window, on=x.index).count()
        )
    
    def _calculate_device_consistency(self, df: pd.DataFrame) -> pd.Series:
        """Calculate device usage consistency"""
        device_counts = df.groupby('user_id')['device_id'].value_counts()
        total_counts = df.groupby('user_id').size()
        
        # Most used device percentage
        max_device_pct = device_counts.groupby(level=0).max() / total_counts
        return max_device_pct
    
    def _get_asset_criticality_map(self) -> Dict[str, float]:
        """Get asset criticality mapping (would come from CMDB)"""
        return {
            'database_server': 10.0,
            'file_server': 7.0,
            'web_server': 5.0,
            'workstation': 2.0,
            'iot_device': 1.0
        }
    
    def normalize_features(self, features: pd.DataFrame, fit: bool = True) -> pd.DataFrame:
        """Normalize features using StandardScaler"""
        if fit:
            scaled = self.scaler.fit_transform(features)
        else:
            scaled = self.scaler.transform(features)
        
        return pd.DataFrame(scaled, columns=features.columns, index=features.index)


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Create sample data
    sample_data = pd.DataFrame({
        'connection_id': range(100),
        'timestamp': pd.date_range('2024-01-01', periods=100, freq='1h'),
        'src_ip': ['192.168.1.10'] * 100,
        'dst_ip': ['10.0.0.1'] * 100,
        'src_port': np.random.randint(1024, 65535, 100),
        'dst_port': [80] * 100,
        'protocol': [6] * 100,  # TCP
        'packets': np.random.randint(1, 100, 100),
        'bytes': np.random.randint(100, 10000, 100),
        'flow_duration': np.random.rand(100) * 100,
    })
    
    config = {
        'features': {
            'network': True,
            'temporal': True
        }
    }
    
    engineer = FeatureEngineer(config)
    features = engineer.extract_all_features(sample_data)
    
    print(f"Extracted {features.shape[1]} features:")
    print(features.head())
