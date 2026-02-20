"""Report generation for security findings

This module provides simplified report generation. For full-featured report generation,
the legacy generate_report() method in SecurityReportGenerator is still used.

This is a placeholder for future modularization of the report generation logic.
"""

from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from pathlib import Path

from scripts.core.findings import Finding, Severity


class ReportGenerator:
    """Generates security reports from findings

    This is a simplified version for the modular architecture.
    The full report generation is still handled by the legacy SecurityReportGenerator
    for backward compatibility.
    """

    def __init__(self, github_context: Optional[Dict[str, str]] = None):
        """Initialize report generator

        Args:
            github_context: GitHub context information (repository, sha, ref, etc.)
        """
        self.github = github_context or {}
        self.findings: Dict[str, List[Finding]] = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        self.tool_stats: Dict[str, Dict[str, Any]] = {}

    def add_findings(self, findings: List[Finding], tool_stats: Dict[str, Any]) -> None:
        """Add findings from a parser

        Args:
            findings: List of Finding objects
            tool_stats: Statistics from the parser
        """
        # Group findings by severity
        for finding in findings:
            severity_key = finding.severity.value.lower()
            if severity_key in self.findings:
                self.findings[severity_key].append(finding)

        # Store tool stats
        tool_name = tool_stats.get('tool', 'unknown')
        self.tool_stats[tool_name.lower().replace(' ', '-')] = tool_stats

    def get_total_findings(self) -> int:
        """Get total number of findings

        Returns:
            Total finding count across all severities
        """
        return sum(len(findings) for findings in self.findings.values())

    def get_severity_counts(self) -> Dict[str, int]:
        """Get counts by severity

        Returns:
            Dictionary mapping severity to count
        """
        return {
            severity: len(findings)
            for severity, findings in self.findings.items()
        }

    def generate_markdown_summary(self, output_file: str) -> None:
        """Generate a simple markdown summary report

        This is a simplified version. For full-featured reports, use the legacy
        SecurityReportGenerator.generate_report() method.

        Args:
            output_file: Path to output markdown file
        """
        total = self.get_total_findings()
        counts = self.get_severity_counts()

        # Determine security posture
        if counts['critical'] > 0:
            posture = 'CRITICAL'
            posture_desc = 'Immediate action required - critical vulnerabilities detected'
        elif counts['high'] > 0:
            posture = 'HIGH'
            posture_desc = 'High-severity issues detected - prompt review needed'
        elif counts['medium'] > 0:
            posture = 'MEDIUM'
            posture_desc = 'Medium-severity issues detected - review recommended'
        elif counts['low'] > 0:
            posture = 'LOW'
            posture_desc = 'Low-severity issues detected - minor improvements suggested'
        else:
            posture = 'CLEAN'
            posture_desc = 'No security issues detected'

        with open(output_file, 'w') as f:
            # Header
            f.write("# Security Scan Report\n\n")
            f.write(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")

            if self.github:
                f.write(f"**Repository:** {self.github.get('repository', 'unknown')}\n\n")
                f.write(f"**Commit:** {self.github.get('sha', 'unknown')}\n\n")
                f.write(f"**Branch:** {self.github.get('ref_name', 'unknown')}\n\n")

            f.write("---\n\n")

            # Executive Summary
            f.write("## Executive Summary\n\n")
            f.write(f"**Security Posture:** {posture}\n\n")
            f.write(f"{posture_desc}\n\n")
            f.write(f"**Total Findings:** {total}\n\n")
            f.write(f"- Critical: {counts['critical']}\n")
            f.write(f"- High: {counts['high']}\n")
            f.write(f"- Medium: {counts['medium']}\n")
            f.write(f"- Low: {counts['low']}\n")
            f.write(f"- Info: {counts['info']}\n\n")

            # Tool Summary
            f.write("## Tool Summary\n\n")
            for tool_key, stats in self.tool_stats.items():
                status = stats.get('status', 'UNKNOWN')
                finding_count = stats.get('findings', 0)
                f.write(f"- **{stats.get('tool', tool_key)}**: {status} ({finding_count} findings)\n")
            f.write("\n")

            # Parser Diagnostics (if any errors occurred)
            parser_errors = [
                (tool_key, stats)
                for tool_key, stats in self.tool_stats.items()
                if 'error' in stats
            ]

            if parser_errors:
                f.write("## 🔍 Parser Diagnostics\n\n")
                f.write("<details>\n")
                f.write(f"<summary>⚠️  {len(parser_errors)} parser(s) encountered errors - Click to expand</summary>\n\n")

                for tool_key, stats in parser_errors:
                    error = stats['error']
                    tool_name = stats.get('tool', tool_key)

                    f.write(f"### {tool_name}\n\n")
                    f.write(f"- **Error Type:** `{error.get('type', 'Unknown')}`\n")
                    f.write(f"- **Message:** {error.get('message', 'No error message')}\n")
                    f.write(f"- **File:** `{error.get('file', 'unknown')}`\n")
                    if error.get('context'):
                        f.write(f"- **Context:** {error['context']}\n")
                    if error.get('traceback'):
                        f.write(f"- **Traceback:**\n```\n{error['traceback']}\n```\n")
                    f.write(f"- **Impact:** This tool's findings may be incomplete or missing\n\n")

                f.write("</details>\n\n")
                f.write("---\n\n")

            # Findings by Severity
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                findings_list = self.findings[severity]
                if not findings_list:
                    continue

                f.write(f"## {severity.upper()} Findings ({len(findings_list)})\n\n")

                for idx, finding in enumerate(findings_list, 1):
                    f.write(f"### {idx}. {finding.rule} ({finding.tool})\n\n")
                    f.write(f"- **File:** `{finding.file}`\n")
                    f.write(f"- **Line:** {finding.line}\n")
                    f.write(f"- **Type:** {finding.type}\n")
                    f.write(f"- **Description:** {finding.description}\n")
                    f.write(f"- **Remediation:** {finding.remediation}\n\n")

    def generate_json_summary(self, output_file: str) -> None:
        """Generate JSON summary for programmatic consumption

        Args:
            output_file: Path to output JSON file
        """
        import json

        # Clean tool_stats to remove non-serializable Finding objects
        clean_tool_stats = {}
        for tool_key, stats in self.tool_stats.items():
            clean_stats = {}
            for key, value in stats.items():
                if key in ('findings_data', 'findings_data_all', 'content', 'breakdown'):
                    # Skip or convert Finding objects
                    if key == 'findings_data' and isinstance(value, list):
                        # Convert Finding objects to dicts if present
                        clean_stats[key] = [
                            f.to_dict() if hasattr(f, 'to_dict') else f
                            for f in value
                        ]
                    elif key == 'findings_data_all' and isinstance(value, list):
                        # Skip large data sets to keep JSON small
                        continue
                    else:
                        clean_stats[key] = value
                else:
                    clean_stats[key] = value
            clean_tool_stats[tool_key] = clean_stats

        summary = {
            'metadata': {
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'repository': self.github.get('repository', 'unknown'),
                'commit': self.github.get('sha', 'unknown'),
                'branch': self.github.get('ref_name', 'unknown'),
            },
            'summary': {
                'total_findings': self.get_total_findings(),
                'by_severity': self.get_severity_counts(),
            },
            'severity_counts': self.get_severity_counts(),  # Add for backward compatibility
            'tools': clean_tool_stats,
            'findings': {
                severity: [f.to_dict() for f in findings]
                for severity, findings in self.findings.items()
            }
        }

        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
