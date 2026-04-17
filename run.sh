#!/bin/bash
# VolatileAI Launch Script
set -e

cd "$(dirname "$0")"
source venv/bin/activate
export PYTHONPATH="$(pwd):$PYTHONPATH"

# Load environment variables from .env if present.
if [ -f ".env" ]; then
	set -a
	# shellcheck disable=SC1091
	source .env
	set +a
fi

# Streamlit app logs.
mkdir -p logs
TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
LOG_FILE="logs/volatileai_${TIMESTAMP}.log"

echo ""
echo "  🧠 VolatileAI — AI-Powered Memory Forensics"
echo "  ─────────────────────────────────────────────"
echo "  Open http://localhost:8502 in your browser"
echo "  Logging to: ${LOG_FILE}"
echo ""

streamlit run app.py 2>&1 | tee -a "${LOG_FILE}"
