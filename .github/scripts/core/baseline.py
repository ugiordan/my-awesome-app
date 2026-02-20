"""Baseline management for acknowledged security findings"""

import os
import sys
import hashlib
from typing import Dict, Any, Optional
import yaml

from scripts.core.findings import Finding


class BaselineManager:
    """Manages acknowledged findings baseline from GitHub Secrets

    This filters out findings that teams have acknowledged as false positives
    or accepted risks. The baseline contains detailed justifications.
    """

    def __init__(self):
        """Initialize baseline manager with empty baseline"""
        self.baseline: Dict[str, list] = {}
        self.baseline_counts: Dict[str, int] = {
            'gitleaks': 0,
            'trufflehog': 0,
            'semgrep': 0,
            'shellcheck': 0,
            'hadolint': 0,
            'yamllint': 0,
            'actionlint': 0,
            'kube-linter': 0,
            'rbac-analyzer': 0
        }
        self.version: str = '1.0'

    def load_from_env(self) -> None:
        """Load acknowledged findings baseline from GitHub Secrets (mandatory)

        Requires:
            SECURITY_BASELINE environment variable (loaded from GitHub Secrets by workflow)

        Raises:
            SystemExit: If SECURITY_BASELINE environment variable is not set
        """
        # Reset baseline counts
        for tool in self.baseline_counts:
            self.baseline_counts[tool] = 0

        # Check for SECURITY_BASELINE environment variable (mandatory)
        baseline_yaml_str = os.getenv('SECURITY_BASELINE')
        if not baseline_yaml_str:
            print("[ERROR] SECURITY_BASELINE environment variable not set", file=sys.stderr)
            print("[ERROR] Baseline must be loaded from GitHub Secrets via workflow", file=sys.stderr)
            print("[ERROR] ", file=sys.stderr)
            print("[ERROR] This should have been set by the 'Load baseline from GitHub Secret' step", file=sys.stderr)
            print("[ERROR] Check workflow logs for baseline loading failures", file=sys.stderr)
            sys.exit(1)

        # Parse baseline from environment variable
        try:
            baseline_data = yaml.safe_load(baseline_yaml_str)
            print("[INFO] Loaded baseline from GitHub Secret (SECURITY_BASELINE env var)", file=sys.stderr)
        except Exception as e:
            print(f"[ERROR] Failed to parse baseline from env var: {str(e)}", file=sys.stderr)
            print("[ERROR] Baseline YAML is invalid", file=sys.stderr)
            sys.exit(1)

        if baseline_data is None:
            print("[INFO] Baseline is empty - all findings will be reported", file=sys.stderr)
            return

        # Validate baseline version
        self.version = baseline_data.get('version', '1.0')
        if self.version != '2.0':
            print(f"[WARNING] Unexpected baseline version: {self.version}, expected 2.0", file=sys.stderr)

        # Store baseline data for each tool
        for tool in self.baseline_counts:
            self.baseline[tool] = baseline_data.get(tool, [])

    def load_from_file(self, filepath: str) -> None:
        """Load baseline from a YAML file (for testing/development)

        Args:
            filepath: Path to baseline YAML file

        Raises:
            FileNotFoundError: If baseline file doesn't exist
            yaml.YAMLError: If baseline YAML is invalid
        """
        # Reset baseline counts
        for tool in self.baseline_counts:
            self.baseline_counts[tool] = 0

        with open(filepath) as f:
            baseline_data = yaml.safe_load(f)

        if baseline_data is None:
            print("[INFO] Baseline is empty - all findings will be reported", file=sys.stderr)
            return

        # Validate baseline version
        self.version = baseline_data.get('version', '1.0')
        if self.version != '2.0':
            print(f"[WARNING] Unexpected baseline version: {self.version}, expected 2.0", file=sys.stderr)

        # Store baseline data for each tool
        for tool in self.baseline_counts:
            self.baseline[tool] = baseline_data.get(tool, [])

    def is_acknowledged(self, tool: str, finding: Dict[str, Any]) -> bool:
        """Check if a finding matches an acknowledged baseline entry

        Args:
            tool: Tool name (gitleaks, trufflehog, semgrep, etc.)
            finding: Finding dict from parser (contains tool-specific fields)

        Returns:
            True if finding is acknowledged in baseline, False otherwise
        """
        if tool not in self.baseline or not self.baseline[tool]:
            return False

        tool_baseline = self.baseline[tool]

        # Tool-specific matching logic (matches acknowledge-findings.py)
        for baseline_entry in tool_baseline:
            if tool == 'gitleaks':
                # Gitleaks findings need description hash for uniqueness
                # Calculate it from finding description
                description = finding.get('description', '')
                desc_hash = hashlib.sha256(description.encode()).hexdigest()[:8]

                if (finding.get('file') == baseline_entry.get('file') and
                    str(finding.get('line')) == str(baseline_entry.get('line')) and
                    finding.get('rule') == baseline_entry.get('rule') and
                    desc_hash == baseline_entry.get('description_hash')):
                    return True

            elif tool == 'trufflehog':
                if (finding.get('detector') == baseline_entry.get('detector') and
                    finding.get('file') == baseline_entry.get('file') and
                    str(finding.get('line')) == str(baseline_entry.get('line'))):
                    return True

            elif tool == 'semgrep' or tool == 'hadolint':
                if (finding.get('rule') == baseline_entry.get('rule_id') and
                    finding.get('file') == baseline_entry.get('file') and
                    str(finding.get('line')) == str(baseline_entry.get('line'))):
                    return True

            elif tool == 'shellcheck':
                if (finding.get('file') == baseline_entry.get('file') and
                    str(finding.get('line')) == str(baseline_entry.get('line')) and
                    finding.get('code') == baseline_entry.get('code')):
                    return True

            elif tool == 'yamllint':
                if (finding.get('file') == baseline_entry.get('file') and
                    str(finding.get('line')) == str(baseline_entry.get('line')) and
                    finding.get('rule') == baseline_entry.get('rule')):
                    return True

            elif tool == 'actionlint':
                if (finding.get('file') == baseline_entry.get('file') and
                    str(finding.get('line')) == str(baseline_entry.get('line')) and
                    finding.get('message') == baseline_entry.get('message')):
                    return True

            elif tool == 'kube-linter':
                # kube-linter uses object kind/name/namespace + check name
                obj = baseline_entry.get('object', {})
                if (finding.get('check') == baseline_entry.get('check') and
                    finding.get('object_kind') == obj.get('kind') and
                    finding.get('object_name') == obj.get('name') and
                    finding.get('object_namespace') == obj.get('namespace')):
                    return True

            elif tool == 'rbac-analyzer':
                if (finding.get('title') == baseline_entry.get('title') and
                    finding.get('file') == baseline_entry.get('file')):
                    return True

        return False

    def mark_acknowledged(self, tool: str) -> None:
        """Increment the baseline count for a tool

        Args:
            tool: Tool name
        """
        if tool in self.baseline_counts:
            self.baseline_counts[tool] += 1

    def get_counts(self) -> Dict[str, int]:
        """Get baseline counts for all tools

        Returns:
            Dictionary mapping tool names to acknowledgment counts
        """
        return self.baseline_counts.copy()

    def get_total_acknowledged(self) -> int:
        """Get total number of acknowledged findings across all tools

        Returns:
            Total acknowledgment count
        """
        return sum(self.baseline_counts.values())
