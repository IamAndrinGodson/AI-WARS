# Quickstart script for ML Threat Detection System (Windows)
# This script sets up the environment and runs a basic test

Write-Host "========================================="
Write-Host "ML Threat Detection System - Quickstart"
Write-Host "========================================="
Write-Host ""

# Check Python version
Write-Host "Checking Python version..."
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ $pythonVersion detected"
} catch {
    Write-Host "Error: Python not found. Please install Python 3.9+ and add it to your PATH." -ForegroundColor Red
    exit 1
}
Write-Host ""

# Create virtual environment if it doesn't exist
if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..."
    python -m venv venv
    Write-Host "✓ Virtual environment created"
} else {
    Write-Host "✓ Virtual environment already exists"
}
Write-Host ""

# Activate virtual environment
Write-Host "Activating virtual environment..."
if (Test-Path "venv\Scripts\Activate.ps1") {
    $env:VIRTUAL_ENV = "$PWD\venv"
    $env:PATH = "$env:VIRTUAL_ENV\Scripts;$env:PATH"
    Write-Host "✓ Virtual environment activated"
} else {
    Write-Host "Error: Could not find activation script in venv\Scripts." -ForegroundColor Red
    exit 1
}
Write-Host ""

# Install dependencies
Write-Host "Installing dependencies (this may take a few minutes)..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
Write-Host "✓ Dependencies installed"
Write-Host ""

# Create necessary directories
Write-Host "Creating directory structure..."
$directories = @("data\raw", "data\processed", "data\models", "logs", "config", "src\dashboard")
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}
Write-Host "✓ Directories created"
Write-Host ""

# Generate synthetic data and train models
Write-Host "========================================="
Write-Host "Training Models (Demo)"
Write-Host "========================================="
Write-Host ""
Write-Host "Generating synthetic data and training models..."
Write-Host "This will take approximately 5-10 minutes..."
Write-Host ""

python scripts/train_models.py --generate-data

Write-Host ""
Write-Host "========================================="
Write-Host "Starting API Server"
Write-Host "========================================="
Write-Host ""
Write-Host "Starting API server on http://localhost:8000"
Write-Host "API documentation will be available at http://localhost:8000/docs"
Write-Host "Dashboard will be available at http://localhost:8000/dashboard/index.html"
Write-Host ""
Write-Host "Press Ctrl+C to stop the server"
Write-Host ""

# Start the API server
python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000
