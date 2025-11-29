#!/bin/bash
# Quick setup script for Mac/Linux users

echo "========================================"
echo "  StudySync - Setup Script"
echo "========================================"
echo ""

echo "[1/3] Installing dependencies..."
python3 -m pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "Error: Failed to install dependencies"
    exit 1
fi

echo ""
echo "[2/3] Initializing database..."
python3 init_db.py
if [ $? -ne 0 ]; then
    echo "Error: Failed to initialize database"
    exit 1
fi

echo ""
echo "[3/3] Setup complete!"
echo ""
echo "========================================"
echo "  Ready to run!"
echo "========================================"
echo ""
echo "To start the application:"
echo "  python3 app.py"
echo ""
echo "Then open your browser to:"
echo "  http://127.0.0.1:5000"
echo ""
