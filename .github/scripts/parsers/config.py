"""Parsers for configuration linters (yamllint, actionlint)"""

import re
from typing import List, Dict, Any

from scripts.parsers.base import BaseParser
from scripts.core.findings import Finding, Severity


class YamllintParser(BaseParser):
    """Parser for yamllint parsable format output"""

    def __init__(self, max_findings: int = 50):
        """Initialize yamllint parser

        Args:
            max_findings: Maximum number of findings to include in report (default: 50)
        """
        super().__init__("yamllint")
        self.max_findings = max_findings

    def parse_file(self, filepath: str) -> tuple[List[Finding], Dict[str, Any]]:
        """Parse yamllint parsable format output

        Format: file:line:column: [level] message (rule)
        Example: ./config/rbac/role.yaml:10:5: [error] line too long (120 > 80 characters) (line-length)

        Args:
            filepath: Path to yamllint parsable output file

        Returns:
            Tuple of (findings_list, stats_dict)
        """
        lines = self.load_text_file(filepath)
        if lines is None:
            return [], self.stats

        findings = []

        try:
            # Pattern: filepath:line:column: [level] message (rule)
            pattern = r'^(.+?):(\d+):(\d+): \[(error|warning)\] (.+?) \(([^)]+)\)$'

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                match = re.match(pattern, line)
                if not match:
                    # Skip lines that don't match expected format
                    continue

                file_path, line_num, col, level, message, rule = match.groups()

                # yamllint findings are typically INFO level (style issues)
                severity = Severity.INFO

                finding = Finding(
                    tool='yamllint',
                    type='YAML Issue',
                    severity=severity,
                    file=file_path,
                    line=int(line_num),
                    rule=rule,
                    description=message,
                    remediation='Follow YAML style guidelines for consistent formatting'
                )
                findings.append(finding)

            self.mark_findings(len(findings))

            # Add metadata about truncation
            self.stats['findings_data'] = findings[:self.max_findings]
            self.stats['findings_data_all'] = findings  # Keep all for dedicated report
            self.stats['truncated'] = len(findings) > self.max_findings
            self.stats['total_findings'] = len(findings)

        except Exception as e:
            self.handle_error(e, "", filepath)

        return findings, self.stats


class ActionlintParser(BaseParser):
    """Parser for actionlint text output"""

    def __init__(self):
        super().__init__("actionlint")

    def parse_file(self, filepath: str) -> tuple[List[Finding], Dict[str, Any]]:
        """Parse actionlint text output

        Format: <file>:<line>:<col>: <message> [<rule>]
        Example: .github/workflows/test.yml:10:5: invalid expression syntax [expression]

        Args:
            filepath: Path to actionlint text output file

        Returns:
            Tuple of (findings_list, stats_dict)
        """
        lines = self.load_text_file(filepath)
        if lines is None:
            return [], self.stats

        findings = []

        try:
            # Pattern: filepath:line:col: message [rule]
            pattern = r'^(.+?):(\d+):(\d+):\s+(.+?)(?:\s+\[(.+?)\])?$'

            # Regex to strip ANSI color codes (e.g., \x1b[31m for red, \x1b[0m for reset)
            ansi_escape = re.compile(r'\x1b\[[0-9;]*m')

            for line in lines:
                if not line.strip():
                    continue

                # Strip ANSI color codes before pattern matching
                clean_line = ansi_escape.sub('', line)

                match = re.match(pattern, clean_line)
                if not match:
                    continue

                file_path, line_num, col, message, rule = match.groups()

                # Map severity based on message content
                # GitHub Actions security issues are generally MEDIUM (workflow errors can break CI/CD)
                severity = Severity.MEDIUM

                # Upgrade to HIGH for security-related issues
                if any(keyword in message.lower() for keyword in ['permission', 'token', 'secret', 'credential']):
                    severity = Severity.HIGH

                finding = Finding(
                    tool='actionlint',
                    type='GitHub Actions Workflow Issue',
                    severity=severity,
                    file=file_path,
                    line=int(line_num),
                    rule=rule or 'workflow-syntax',
                    description=message,
                    remediation='Fix GitHub Actions workflow syntax according to actionlint recommendation'
                )
                findings.append(finding)

            self.mark_findings(len(findings))
            self.stats['findings_data'] = findings  # Store findings for dedicated report

        except Exception as e:
            self.handle_error(e, "", filepath)

        return findings, self.stats
