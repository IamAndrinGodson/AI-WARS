# Training Guide: ML Threat Detection System

This guide provides step-by-step instructions for training and deploying the ML-based threat detection models.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Data Preparation](#data-preparation)
3. [Model Training](#model-training)
4. [Model Evaluation](#model-evaluation)
5. [Deployment](#deployment)
6. [Monitoring & Maintenance](#monitoring--maintenance)

---

## Prerequisites

### System Requirements

- **Hardware**:
  - CPU: 8+ cores recommended
  - RAM: 16GB minimum, 32GB recommended
  - Storage: 100GB+ for data and models
  - GPU: Optional but recommended for deep learning models

- **Software**:
  - Python 3.9 or higher
  - Docker & Docker Compose
  - Git

### Installation

1. **Clone the repository**:
```bash
git clone <repository-url>
cd ml-threat-detection-system
```

2. **Create virtual environment**:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Verify installation**:
```bash
python -c "import tensorflow; import sklearn; import xgboost; print('All packages installed successfully!')"
```

---

## Data Preparation

### Step 1: Understand Data Requirements

The system requires network security data with the following features:

**Required Fields**:
- `timestamp`: Event timestamp
- `src_ip`: Source IP address
- `dst_ip`: Destination IP address
- `src_port`: Source port
- `dst_port`: Destination port
- `protocol`: Protocol number (6=TCP, 17=UDP)
- `packets`: Packet count
- `bytes`: Byte count
- `flow_duration`: Flow duration in seconds

**Optional Fields (improve accuracy)**:
- `label`: Threat classification (for supervised learning)
- `user_id`: User identifier
- `asset_id`: Asset identifier
- `geolocation`: Geographic location
- `device_id`: Device identifier

### Step 2: Data Collection

**Option A: Use Existing Data**

If you have network flow data from NetFlow, sFlow, or SIEM:

```bash
# Place your data in the data/raw directory
cp /path/to/your/data/*.parquet data/raw/
# or
cp /path/to/your/data/*.csv data/raw/
```

**Option B: Generate Synthetic Data (for testing)**

```bash
# Generate 10,000 training samples
python scripts/train_models.py --generate-data

# This creates:
# - data/raw/synthetic_train.parquet (10,000 samples)
# - data/processed/synthetic_test.parquet (2,000 samples)
```

### Step 3: Data Quality Check

```bash
# Check data format and statistics
python scripts/check_data.py --input data/raw/

# Expected output:
# ✓ Data shape: (10000, 11)
# ✓ Required columns present
# ✓ No missing values
# ✓ Data types correct
```

### Step 4: Data Preprocessing

The training script automatically handles:
- Missing value imputation
- Feature scaling/normalization
- Temporal feature extraction
- Categorical encoding

---

## Model Training

### Step 1: Configure Training Parameters

Edit `config/config.yaml` to customize training:

```yaml
models:
  anomaly_detection:
    isolation_forest:
      n_estimators: 200      # Number of trees
      contamination: 0.01    # Expected anomaly rate
    
    autoencoder:
      encoding_dim: 32       # Bottleneck dimension
      epochs: 100            # Training epochs
      batch_size: 256
    
    lstm:
      units: 64              # LSTM units
      sequence_length: 50    # Sequence length
      epochs: 50
  
  classification:
    xgboost:
      max_depth: 7
      learning_rate: 0.1
      n_estimators: 200
```

### Step 2: Train All Models

**Basic Training (with synthetic data)**:
```bash
python scripts/train_models.py --generate-data
```

**Training with Your Data**:
```bash
python scripts/train_models.py \
    --config config/config.yaml \
    --data data/raw/your_data.parquet \
    --test-data data/processed/test_data.parquet
```

**Training Output**:
```
========================================================
Starting Full Training Pipeline
========================================================
[INFO] Loading data from data/raw/synthetic_train.parquet
[INFO] Loaded 10000 records with 11 columns
[INFO] Extracting features...
[INFO] Prepared 45 features
========================================================
Training Anomaly Detection Models
========================================================
[INFO] Training Isolation Forest on 10000 samples
[INFO] Isolation Forest training complete
[INFO] Training Autoencoder on 10000 samples
Epoch 1/100
[INFO] Training LSTM on 10000 samples
[INFO] Anomaly detection models saved to data/models/anomaly_detector
========================================================
Training Threat Classification Models
========================================================
[INFO] Training xgboost...
[INFO] xgboost - Train: 0.9850, Val: 0.9700
[INFO] Training lightgbm...
[INFO] lightgbm - Train: 0.9820, Val: 0.9680
[INFO] Threat classification models saved to data/models/threat_classifier
========================================================
Evaluating Models
========================================================
[INFO] Anomaly Detection:
[INFO]   Detected 95 anomalies out of 2000 samples
[INFO]   Score range: [0.012, 0.987]
[INFO] Threat Classification:
[INFO]   Overall Accuracy: 0.9700
[INFO]   Macro F1-Score: 0.9650
========================================================
Training Pipeline Completed Successfully!
========================================================
```

### Step 3: Understanding Model Outputs

After training, the following models are saved:

```
data/models/
├── anomaly_detector/
│   ├── isolation_forest.pkl
│   ├── autoencoder_model.h5
│   ├── autoencoder_data.pkl
│   ├── lstm_model.h5
│   └── lstm_data.pkl
└── threat_classifier/
    ├── xgboost.pkl
    ├── lightgbm.pkl
    ├── random_forest.pkl
    ├── gradient_boosting.pkl
    └── metadata.pkl
```

### Step 4: Training Time Estimates

| Dataset Size | Hardware | Training Time |
|-------------|----------|---------------|
| 10K samples | CPU (8 cores) | ~5-10 minutes |
| 100K samples | CPU (8 cores) | ~30-60 minutes |
| 1M samples | CPU (8 cores) | ~3-6 hours |
| 10K samples | GPU (NVIDIA) | ~2-5 minutes |
| 100K samples | GPU (NVIDIA) | ~10-20 minutes |

---

## Model Evaluation

### Step 1: Evaluate on Test Data

```bash
python scripts/evaluate_models.py \
    --test-data data/processed/test_data.parquet \
    --output-dir logs/evaluation/
```

### Step 2: Review Metrics

Check the evaluation report:

```bash
cat logs/evaluation/evaluation_report.txt
```

**Expected Metrics**:

```
Anomaly Detection:
  Precision: 0.92
  Recall: 0.88
  F1-Score: 0.90
  AUC-ROC: 0.95

Threat Classification:
  Accuracy: 0.97
  
  Per-Class Metrics:
  ┌─────────────────────┬───────────┬────────┬─────────┐
  │ Class               │ Precision │ Recall │ F1-Score│
  ├─────────────────────┼───────────┼────────┼─────────┤
  │ normal              │ 0.99      │ 0.98   │ 0.98    │
  │ dos                 │ 0.95      │ 0.94   │ 0.94    │
  │ port_scan           │ 0.92      │ 0.91   │ 0.91    │
  │ brute_force         │ 0.96      │ 0.95   │ 0.95    │
  │ malware             │ 0.98      │ 0.97   │ 0.97    │
  │ data_exfiltration   │ 0.97      │ 0.96   │ 0.96    │
  └─────────────────────┴───────────┴────────┴─────────┘
```

### Step 3: Confusion Matrix Analysis

```python
# View confusion matrix
python scripts/plot_confusion_matrix.py \
    --test-data data/processed/test_data.parquet
```

### Step 4: Feature Importance

```python
# Analyze feature importance
python scripts/analyze_features.py \
    --model data/models/threat_classifier/xgboost.pkl
```

---

## Deployment

### Step 1: Start Services with Docker

```bash
# Build and start all services
docker-compose up -d

# Check service status
docker-compose ps

# Expected output:
# NAME                           STATUS    PORTS
# threat-detection-api           Up        0.0.0.0:8000->8000/tcp
# threat-detection-elasticsearch Up        0.0.0.0:9200->9200/tcp
# threat-detection-redis         Up        0.0.0.0:6379->6379/tcp
# threat-detection-kafka         Up        0.0.0.0:9092->9092/tcp
# threat-detection-prometheus    Up        0.0.0.0:9090->9090/tcp
# threat-detection-grafana       Up        0.0.0.0:3000->3000/tcp
```

### Step 2: Verify API

```bash
# Health check
curl http://localhost:8000/health

# Expected response:
{
  "status": "healthy",
  "timestamp": "2024-01-30T10:00:00Z",
  "models": {
    "anomaly_detector": true,
    "threat_classifier": true,
    "feature_engineer": true,
    "response_engine": true
  }
}
```

### Step 3: Test Detection

```bash
# Send test request
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {
        "timestamp": "2024-01-30T10:00:00Z",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.50",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": 6,
        "packets": 100,
        "bytes": 50000,
        "flow_duration": 10.5
      }
    ]
  }'
```

### Step 4: Access Dashboards

- **API Documentation**: http://localhost:8000/docs
- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090
- **Elasticsearch**: http://localhost:9200

---

## Monitoring & Maintenance

### Continuous Learning

The system should be retrained periodically to adapt to evolving threats:

```bash
# Schedule weekly retraining (cron job)
0 2 * * 0 cd /path/to/ml-threat-detection-system && python scripts/retrain_models.py

# Or use the built-in scheduler
python scripts/scheduler.py --retrain-frequency weekly
```

### Performance Monitoring

```bash
# View real-time metrics
python scripts/monitor_performance.py

# Check model drift
python scripts/detect_drift.py \
    --baseline data/models/baselines/ \
    --current data/processed/recent/
```

### Model Versioning

```bash
# List model versions
ls -lh data/models/versions/

# Compare versions
python scripts/compare_models.py \
    --model1 data/models/versions/v1.0/ \
    --model2 data/models/versions/v1.1/
```

### Troubleshooting

**Low Accuracy**:
- Increase training data (minimum 10,000 samples)
- Adjust contamination parameter
- Feature engineering improvements
- Hyperparameter tuning

**High False Positives**:
- Establish better baselines (need 2-4 weeks of normal data)
- Adjust threshold parameters
- Enable false positive reduction

**Slow Predictions**:
- Use GPU acceleration
- Reduce batch size
- Optimize feature extraction
- Consider model compression

---

## Advanced Topics

### Custom Feature Engineering

```python
# Add custom features
# Edit src/features/feature_generator.py

def extract_custom_features(self, df):
    features = pd.DataFrame()
    
    # Your custom logic here
    features['my_custom_feature'] = df['packets'] / df['bytes']
    
    return features
```

### Transfer Learning

```python
# Use pre-trained models
python scripts/transfer_learning.py \
    --pretrained data/models/pretrained/ \
    --finetune data/raw/your_data.parquet
```

### Federated Learning

```python
# Enable federated learning (privacy-preserving)
python scripts/federated_training.py \
    --config config/federated_config.yaml
```

---

## Next Steps

1. ✅ Complete initial training
2. ✅ Deploy API
3. ✅ Integrate with existing infrastructure
4. ⏳ Establish baselines (2-4 weeks)
5. ⏳ Enable automated response
6. ⏳ Continuous monitoring and improvement

For questions or issues, refer to:
- [Documentation](docs/)
- [FAQ](docs/faq.md)
- [Troubleshooting Guide](docs/troubleshooting.md)
