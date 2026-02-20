#!/usr/bin/env python3
# Plugin Version: 2.3.0
# DO NOT REMOVE: This comment is used for version detection during plugin updates
"""
Comprehensive Security Report Generator

Thin wrapper for backward compatibility. Delegates to modular implementation.

Usage:
    python generate-security-report.py --output security-report.md
"""

import sys
import os
from pathlib import Path

# Ensure scripts directory is in path for package imports
# This file is at: .github/scripts/generate-security-report.py
# We need to add .github to sys.path so we can import scripts.cli.report
scripts_dir = Path(__file__).resolve().parent  # .github/scripts
github_dir = scripts_dir.parent  # .github

# Add .github to path to support package imports
if str(github_dir) not in sys.path:
    sys.path.insert(0, str(github_dir))

# Import and run modular implementation
from scripts.cli.report import main

if __name__ == '__main__':
    sys.exit(main())
