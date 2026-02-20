#!/bin/bash
# Test runner for security scanning modules
# Sets up proper PYTHONPATH for relative imports

set -e

# Get the .github directory (parent of scripts)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GITHUB_DIR="$(dirname "$SCRIPT_DIR")"

# Set PYTHONPATH to .github directory to enable scripts.* imports
export PYTHONPATH="$GITHUB_DIR"

# Run tests
cd "$GITHUB_DIR"
python3 -m scripts.run_tests

echo ""
echo "All tests completed successfully!"
