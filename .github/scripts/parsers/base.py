"""Base parser class for security scanning tools"""

import os
import json
import sys
import traceback
import html
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Any, Optional

# Ensure package imports work
scripts_dir = Path(__file__).resolve().parent.parent
github_dir = scripts_dir.parent
if str(github_dir) not in sys.path:
    sys.path.insert(0, str(github_dir))

from scripts.core.findings import Finding, Severity


class BaseParser(ABC):
    """Abstract base class for security tool parsers

    Provides common functionality for parsing security tool outputs:
    - Path normalization
    - File existence checking
    - Error handling
    - Statistics tracking
    """

    def __init__(self, tool_name: str):
        """Initialize parser

        Args:
            tool_name: Name of the security tool (e.g., "Gitleaks", "Semgrep")
        """
        self.tool_name = tool_name
        self.stats = {
            'tool': tool_name,
            'findings': 0,
            'status': '✅ PASS'
        }

    @staticmethod
    def normalize_path(file_path: str) -> str:
        """Normalize file path for consistent baseline matching

        Handles:
        - Docker container mount paths (/repo/)
        - Absolute paths
        - Relative paths with . and ..
        - Path separators

        Args:
            file_path: Raw file path from tool output

        Returns:
            Normalized relative path from repository root
        """
        # Strip /repo/ prefix from Docker container mount path
        if file_path.startswith('/repo/'):
            file_path = file_path[6:]  # Remove '/repo/' prefix

        # Normalize path using os.path.normpath for robust handling
        file_path = os.path.normpath(file_path).lstrip('/')

        # Ensure no leading path traversal after normalization
        while file_path.startswith('../') or file_path.startswith('./'):
            if file_path.startswith('../'):
                file_path = file_path[3:]
            elif file_path.startswith('./'):
                file_path = file_path[2:]

        return file_path

    def file_exists(self, filepath: str) -> bool:
        """Check if output file exists

        Args:
            filepath: Path to tool output file

        Returns:
            True if file exists, False otherwise (updates stats)
        """
        if not Path(filepath).exists():
            self.stats['status'] = '⏭️ SKIPPED'
            return False
        return True

    def handle_error(self, error: Exception, context: str = "", filepath: str = "") -> None:
        """Handle parsing errors consistently

        Args:
            error: Exception that occurred
            context: Additional context for error message
            filepath: Path to file that caused the error
        """
        self.stats['status'] = f'⚠️ ERROR: Failed to parse {self.tool_name} output'

        # Sanitize error message to prevent markdown injection (truncate to 500 chars)
        error_message = html.escape(str(error))[:500]
        if len(str(error)) > 500:
            error_message += "..."

        # Normalize filepath for consistent reporting
        normalized_filepath = self.normalize_path(filepath) if filepath else 'unknown'

        # Store structured error information for report generation
        self.stats['error'] = {
            'message': error_message,
            'type': error.__class__.__name__,
            'context': html.escape(context) if context else "",
            'file': normalized_filepath
        }

        # Add traceback for debugging (only in verbose/debug mode)
        if os.getenv('SECURITY_SCAN_DEBUG', '').lower() in ('true', '1', 'yes'):
            self.stats['error']['traceback'] = traceback.format_exc()

        # Log to stderr for workflow logs
        error_msg = f"[ERROR] {self.tool_name} parser"
        if context:
            error_msg += f" ({context})"
        error_msg += f": {str(error)}"
        print(error_msg, file=sys.stderr)

    def mark_findings(self, count: int) -> None:
        """Update stats with findings count

        Args:
            count: Number of findings detected
        """
        self.stats['findings'] = count
        if count > 0:
            self.stats['status'] = '❌ FINDINGS'

    @abstractmethod
    def parse_file(self, filepath: str) -> tuple[List[Finding], Dict[str, Any]]:
        """Parse tool output file and extract findings

        Args:
            filepath: Path to tool output file

        Returns:
            Tuple of (findings_list, stats_dict)
            - findings_list: List of Finding objects
            - stats_dict: Parser statistics (tool, findings count, status)

        Raises:
            NotImplementedError: Must be implemented by subclass
        """
        raise NotImplementedError("Subclasses must implement parse_file()")

    def load_json_file(self, filepath: str) -> Optional[Any]:
        """Load and parse JSON file

        Args:
            filepath: Path to JSON file

        Returns:
            Parsed JSON data, or None if file doesn't exist or parsing fails
        """
        if not self.file_exists(filepath):
            return None

        try:
            with open(filepath) as f:
                return json.load(f)
        except Exception as e:
            self.handle_error(e, "JSON parsing", filepath)
            return None

    def load_text_file(self, filepath: str) -> Optional[List[str]]:
        """Load text file as list of lines

        Args:
            filepath: Path to text file

        Returns:
            List of lines, or None if file doesn't exist or reading fails
        """
        if not self.file_exists(filepath):
            return None

        try:
            with open(filepath) as f:
                return f.readlines()
        except Exception as e:
            self.handle_error(e, "text file reading", filepath)
            return None

    def deduplicate_findings(self, findings: List[Finding], key_func=None) -> List[Finding]:
        """Deduplicate findings based on key function

        Args:
            findings: List of findings to deduplicate
            key_func: Function to generate deduplication key (default: file:line:rule)

        Returns:
            Deduplicated list of findings
        """
        if key_func is None:
            # Default deduplication key
            key_func = lambda f: f"{f.file}:{f.line}:{f.rule}"

        seen = set()
        unique_findings = []

        for finding in findings:
            key = key_func(finding)
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        return unique_findings
