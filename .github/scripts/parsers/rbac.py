"""Parser for RBAC Analyzer output"""

import re
from typing import List, Dict, Any

from scripts.parsers.base import BaseParser
from scripts.core.findings import Finding, Severity


class RBACAnalyzerParser(BaseParser):
    """Parser for RBAC Analyzer text output (markdown format)"""

    def __init__(self):
        super().__init__("RBAC Analyzer")

    def parse_file(self, filepath: str) -> tuple[List[Finding], Dict[str, Any]]:
        """Parse RBAC Analyzer text output

        The output is in markdown format with severity sections and individual findings.
        Example:
        ### CRITICAL (2 findings)
        1. **Wildcard Resources in ClusterRole**
           - File: `config/rbac/role.yaml`
           - Issue: ClusterRole grants wildcard access to all resources
           - Fix: Specify exact resources needed

        Args:
            filepath: Path to RBAC Analyzer output file

        Returns:
            Tuple of (findings_list, stats_dict)
        """
        lines = self.load_text_file(filepath)
        if lines is None:
            return [], self.stats

        findings = []
        breakdown = {
            'critical': 0,
            'high': 0,
            'warning': 0,
            'info': 0
        }

        try:
            content = ''.join(lines)
            self.stats['content'] = content

            # Parse individual RBAC findings from markdown
            severity_pattern = r'### (CRITICAL|HIGH|WARNING|INFO) \((\d+) findings?\)'
            finding_pattern = r'\d+\. \*\*(.+?)\*\*\s*\n\s*- File: `(.+?)`\s*\n\s*- Issue: (.+?)\n\s*- Fix: (.+?)(?=\n\n|\n\d+\.|\Z)'

            # Split by severity sections
            sections = re.split(severity_pattern, content)

            for i in range(1, len(sections), 3):
                severity_str = sections[i]
                section_content = sections[i+2] if i+2 < len(sections) else ''

                # Map severity string to Severity enum
                severity_map = {
                    'CRITICAL': Severity.CRITICAL,
                    'HIGH': Severity.HIGH,
                    'WARNING': Severity.MEDIUM,
                    'INFO': Severity.INFO
                }
                severity = severity_map.get(severity_str, Severity.INFO)

                # Map severity to bucket for breakdown
                bucket_map = {
                    'CRITICAL': 'critical',
                    'HIGH': 'high',
                    'WARNING': 'warning',
                    'INFO': 'info'
                }
                severity_bucket = bucket_map.get(severity_str, 'info')

                # Extract individual findings from this severity section
                for match in re.finditer(finding_pattern, section_content, re.DOTALL):
                    title = match.group(1).strip()
                    file_path = match.group(2).strip()
                    issue = match.group(3).strip()
                    fix = match.group(4).strip()

                    finding = Finding(
                        tool='RBAC Analyzer',
                        type='RBAC Privilege Chain',
                        severity=severity,
                        file=file_path,
                        line='?',
                        rule=f'RBAC_ANALYZER_{severity_str}',
                        description=issue,
                        remediation=fix,
                        title=title  # Required for baseline matching
                    )
                    findings.append(finding)
                    breakdown[severity_bucket] += 1

            self.mark_findings(len(findings))
            self.stats['breakdown'] = breakdown

        except Exception as e:
            self.handle_error(e, "", filepath)

        return findings, self.stats
