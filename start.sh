#!/bin/bash
# Quick start script - checks if setup is needed

if [ ! -f "sessions.db" ]; then
    echo "========================================"
    echo "  Database not found!"
    echo "========================================"
    echo ""
    echo "It looks like you haven't run setup yet."
    echo ""
    read -p "Would you like to run setup now? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        ./setup.sh
    else
        echo "Please run ./setup.sh first, then try again."
        exit 1
    fi
fi

echo "Starting StudySync..."
python3 app.py
