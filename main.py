"""
Smart Airport Security System - Entry Point
Run this to start the full system with web dashboard.
Usage: python main.py
"""
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import sys
import uvicorn
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from backend.config import HOST, PORT


def main():
    print("\n" + "=" * 55)
    print("   SMART AIRPORT SECURITY SYSTEM v2.0")
    print("   AI-Powered Surveillance & Criminal Detection")
    print("=" * 55)
    print(f"\n   Dashboard: http://{HOST}:{PORT}")
    print(f"   Video Feed: http://{HOST}:{PORT}/api/video/CAM-001")
    print(f"   API Docs: http://{HOST}:{PORT}/docs")
    print("\n" + "=" * 55 + "\n")

    uvicorn.run(
        "backend.app:app",
        host=HOST,
        port=PORT,
        reload=False,
        log_level="info"
    )


if __name__ == "__main__":
    main()