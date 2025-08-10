#!/bin/bash
set -e
echo "🔹 Updating pip..."
python -m pip install --upgrade pip wheel
echo "🔹 Installing deps..."
python -m pip install -r requirements.txt
echo "✅ Setup complete."
