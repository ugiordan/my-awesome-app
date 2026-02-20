"""Parsers for infrastructure scanning tools (Hadolint, ShellCheck)"""

from typing import List, Dict, Any

from scripts.parsers.base import BaseParser
from scripts.core.findings import Finding, Severity


class HadolintParser(BaseParser):
    """Parser for Hadolint SARIF output"""

    def __init__(self):
        super().__init__("Hadolint")

    def parse_file(self, filepath: str) -> tuple[List[Finding], Dict[str, Any]]:
        """Parse Hadolint SARIF output

        Args:
            filepath: Path to Hadolint SARIF output file

        Returns:
            Tuple of (findings_list, stats_dict)
        """
        sarif = self.load_json_file(filepath)
        if sarif is None:
            return [], self.stats

        findings = []

        try:
            for run in sarif.get('runs', []):
                for result in run.get('results', []):
                    level = result.get('level', 'note')
                    severity_map = {
                        'error': Severity.HIGH,
                        'warning': Severity.MEDIUM,
                        'note': Severity.LOW
                    }
                    severity = severity_map.get(level, Severity.LOW)

                    rule = result.get('ruleId', 'unknown')
                    message = result.get('message', {}).get('text', 'No description')

                    locations = result.get('locations') or []
                    location = locations[0] if locations else {}
                    artifact = location.get('physicalLocation', {}).get('artifactLocation', {})
                    file_path = artifact.get('uri', 'unknown')

                    region = location.get('physicalLocation', {}).get('region', {})
                    line = region.get('startLine', '?')

                    finding = Finding(
                        tool='Hadolint',
                        type='Dockerfile Issue',
                        severity=severity,
                        file=file_path,
                        line=line,
                        rule=rule,
                        description=message,
                        remediation='Follow Dockerfile best practices and CIS benchmarks'
                    )
                    findings.append(finding)

            self.mark_findings(len(findings))

        except Exception as e:
            self.handle_error(e, "", filepath)

        return findings, self.stats


class ShellCheckParser(BaseParser):
    """Parser for ShellCheck JSON output"""

    def __init__(self):
        super().__init__("ShellCheck")

    def parse_file(self, filepath: str) -> tuple[List[Finding], Dict[str, Any]]:
        """Parse ShellCheck JSON output

        Supports both legacy format (flat list) and json1 format ({comments: [...]})

        Args:
            filepath: Path to ShellCheck JSON output file

        Returns:
            Tuple of (findings_list, stats_dict)
        """
        data = self.load_json_file(filepath)
        if data is None:
            return [], self.stats

        findings = []

        try:
            # ShellCheck outputs either a flat list (legacy) or {comments: [...]} (json1)
            # Support both formats robustly
            if isinstance(data, list):
                findings_iter = data
            elif isinstance(data, dict):
                # Check for json1 format with 'comments' key, or fall back to iterating all values
                if 'comments' in data:
                    findings_iter = data['comments']
                else:
                    findings_iter = [item for v in data.values() if isinstance(v, list) for item in v]
            else:
                findings_iter = []

            for finding_data in findings_iter:
                level = finding_data.get('level', 'info')
                severity_map = {
                    'error': Severity.HIGH,
                    'warning': Severity.MEDIUM,
                    'info': Severity.LOW,
                    'style': Severity.INFO
                }
                severity = severity_map.get(level, Severity.LOW)

                code = finding_data.get('code')

                finding = Finding(
                    tool='ShellCheck',
                    type='Shell Script Issue',
                    severity=severity,
                    file=finding_data.get('file', 'unknown'),
                    line=finding_data.get('line', '?'),
                    rule=f"SC{code if code else '????'}",
                    description=finding_data.get('message', 'No description'),
                    remediation='Follow ShellCheck recommendations for safe shell scripting',
                    code=code  # For baseline matching
                )
                findings.append(finding)

            self.mark_findings(len(findings))

        except Exception as e:
            self.handle_error(e, "", filepath)

        return findings, self.stats
