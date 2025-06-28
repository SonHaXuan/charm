#!/usr/bin/env python3
"""
Runner script for the hybrid ABENC (DACMACS) encryption benchmark.
Usage: python run_abenc_benchmark.py
"""

import sys
import os
import traceback

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from benchmark_hybrid_abenc_dacmacs import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user.")
    except Exception as e:
        print(f"Error running ABENC benchmark: {e}")
        print("\nFull traceback:")
        traceback.print_exc()
        sys.exit(1)
