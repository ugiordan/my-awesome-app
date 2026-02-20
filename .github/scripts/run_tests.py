#!/usr/bin/env python3
"""Test runner for security scanning modules

This script runs tests with proper PYTHONPATH setup to handle relative imports.
"""

import sys
from pathlib import Path

# Add the scripts directory to Python path for proper imports
scripts_dir = Path(__file__).parent
sys.path.insert(0, str(scripts_dir))

# Now we can import and run tests
from tests.test_parsers import run_tests

if __name__ == '__main__':
    run_tests()
