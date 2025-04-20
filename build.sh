#!/usr/bin/env bash
# exit on error
set -o errexit

# Install system dependencies (Tesseract OCR and Poppler for PDF processing)
apt-get update
apt-get install -y tesseract-ocr
apt-get install -y poppler-utils

# Install Python dependencies
poetry install

# Create the database tables (if they don't exist)
python -c "from main import app, db; app.app_context().push(); db.create_all()"