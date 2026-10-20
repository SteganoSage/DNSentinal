"""
Direct runner script for the DNSentinel Dashboard Backend.
Usage:
    py dashboard/backend/run_backend.py
"""

import sys
import os
from pathlib import Path

# Add current backend folder to python path and working directory
BACKEND_DIR = Path(__file__).resolve().parent
os.chdir(BACKEND_DIR)
sys.path.insert(0, str(BACKEND_DIR))

import uvicorn

if __name__ == "__main__":
    print("=" * 60)
    print("  DNSentinel Cybersecurity Gateway - Dashboard Server")
    print("  Mode: DEMO / SAMPLE DATA")
    print("  Local URL: http://127.0.0.1:8000")
    print("  API Docs:  http://127.0.0.1:8000/docs")
    print("=" * 60)
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
