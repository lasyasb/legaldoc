#!/usr/bin/env bash
# exit on error
set -o errexit

# Install system dependencies needed for document processing
apt-get update
apt-get install -y tesseract-ocr
apt-get install -y poppler-utils

# Install Python dependencies
pip install --upgrade pip
pip install -r render-requirements.txt