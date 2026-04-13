#!/bin/bash
# VolatileAI Launch Script
cd "$(dirname "$0")"
source venv/bin/activate
export PYTHONPATH="$(pwd):$PYTHONPATH"
echo ""
echo "  🧠 VolatileAI — AI-Powered Memory Forensics"
echo "  ─────────────────────────────────────────────"
echo "  Open http://localhost:8502 in your browser"
echo ""
streamlit run app.py
