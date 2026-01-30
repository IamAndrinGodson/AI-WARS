#!/bin/bash

# Quickstart script for ML Threat Detection System
# This script sets up the environment and runs a basic test

set -e  # Exit on error

echo "========================================="
echo "ML Threat Detection System - Quickstart"
echo "========================================="
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python --version 2>&1 | awk '{print $2}')
echo "✓ Python $python_version detected"
echo ""

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi
echo ""

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate
echo "✓ Virtual environment activated"
echo ""

# Install dependencies
echo "Installing dependencies (this may take a few minutes)..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "✓ Dependencies installed"
echo ""

# Create necessary directories
echo "Creating directory structure..."
mkdir -p data/{raw,processed,models} logs config
echo "✓ Directories created"
echo ""

# Generate synthetic data and train models
echo "========================================="
echo "Training Models (Demo)"
echo "========================================="
echo ""
echo "Generating synthetic data and training models..."
echo "This will take approximately 5-10 minutes..."
echo ""

python scripts/train_models.py --generate-data

echo ""
echo "========================================="
echo "Starting API Server"
echo "========================================="
echo ""
echo "Starting API server on http://localhost:8000"
echo "API documentation will be available at http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Start the API server
python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000
