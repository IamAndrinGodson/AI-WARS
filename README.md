# ML-Based Threat Detection System

A comprehensive, production-ready machine learning system for cybersecurity threat detection and automated response.

## 🎯 Overview

This system implements state-of-the-art ML techniques for:
- Real-time network anomaly detection
- Zero-day threat identification
- Automated incident response
- Behavioral analytics (UEBA)
- Threat intelligence and prediction

## 🏗️ Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Data Sources   │────▶│  Data Pipeline   │────▶│ Feature Engine  │
│ (NetFlow/SIEM)  │     │  (Collectors)    │     │  (Engineering)  │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                           │
                                                           ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Dashboard     │◀────│   ML Models      │◀────│   Baselines     │
│  (Explainable)  │     │ (Ensemble/Deep)  │     │  (UEBA/Zones)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │ Response Engine  │
                        │ (SOAR/Automated) │
                        └──────────────────┘
```

## 🚀 Quick Start (Windows & Linux)

### Instant Setup (Recommended)

**Windows (PowerShell):**
```powershell
.\quickstart.ps1
```

**Linux / Mac (Bash):**
```bash
./quickstart.sh
```

These scripts will automatically:
1. Check Python version.
2. Create and activate a virtual environment.
3. Install all dependencies.
4. Generate synthetic training data.
5. Train the machine learning models.
6. Start the API server and Dashboard.

---

### Manual Installation & Running

If you prefer to run steps manually or need to troubleshoot:

#### 1. Environment Setup

**Clone and enter directory:**
```bash
git clone <repository>
cd ml-threat-detection-system
```

**Create and Activate Virtual Environment:**

*Windows:*
```powershell
python -m venv venv
.\venv\Scripts\Activate
```

*Linux/Mac:*
```bash
python3 -m venv venv
source venv/bin/activate
```

**Install Dependencies:**
```bash
pip install -r requirements.txt
```

#### 2. Data Generation & Model Training

Before running the API, you must generate data and train the initial models:

```bash
python scripts/train_models.py --generate-data
```
*This command generates synthetic traffic data, processes it, and trains the anomaly detection and classifier models.*

#### 3. Start the System

Run the API server (which also serves the Dashboard):

```bash
python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000
```

#### 4. Access the Dashboard

Open your browser and navigate to:
**[http://localhost:8000/dashboard/index.html](http://localhost:8000/dashboard/index.html)**

API Documentation (Swagger UI) is available at:
**[http://localhost:8000/docs](http://localhost:8000/docs)**

## 📋 Features

### Phase 1: Data Pipeline
- Multi-source data collection (NetFlow, sFlow, SIEM, endpoints)
- Scalable data lake with retention policies
- Real-time and batch processing
- Feature engineering framework

### Phase 2: ML Models
- **Anomaly Detection**: Isolation Forest, Autoencoders, LSTM
- **Threat Classification**: Multi-class ensemble models
- **Graph Analysis**: GNN for network relationships
- **Zero-Day Detection**: Behavioral divergence scoring

### Phase 3: Intelligent Response
- Multi-factor risk scoring
- Attack chain reconstruction
- Automated tiered responses
- Explainable AI dashboards

### Phase 4: Production Operations
- Continuous learning and model retraining
- Human-AI collaboration interface
- Compliance and audit trails
- Performance monitoring

## 🔧 Configuration

Key configuration files:
- `config/config.yaml`: Main system configuration
- `config/training_config.yaml`: Model training parameters
- `config/detection_rules.yaml`: Detection thresholds and rules
- `config/response_actions.yaml`: Automated response configurations

## 📊 Monitoring & Operations

### Access Dashboard
```bash
# Start web interface
python src/api/app.py

# Access at http://localhost:8000/dashboard/index.html
```

### Performance Metrics
- Model accuracy, precision, recall tracked in `logs/metrics/`
- Real-time dashboards available at `/metrics` endpoint
- Prometheus/Grafana integration supported

## 🧪 Testing

```bash
# Run all tests
pytest tests/
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.
