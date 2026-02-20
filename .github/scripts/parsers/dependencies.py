"""Parsers for dependency scanning tools (govulncheck, pip-audit)"""

from typing import List, Dict, Any

from scripts.parsers.base import BaseParser
from scripts.core.findings import Finding, Severity


class GovulncheckParser(BaseParser):
    """Parser for govulncheck SARIF output"""

    def __init__(self):
        super().__init__("govulncheck")

    def parse_file(self, filepath: str) -> tuple[List[Finding], Dict[str, Any]]:
        """Parse govulncheck SARIF output

        Args:
            filepath: Path to govulncheck SARIF output file

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
                    # Map SARIF level to severity
                    level = result.get('level', 'note')
                    severity = self._map_sarif_level(level)

                    rule_id = result.get('ruleId', 'UNKNOWN-VULN')
                    message = result.get('message', {}).get('text', 'Vulnerability in dependency')

                    # Extract location (usually go.mod)
                    locations = result.get('locations') or []
                    if locations:
                        location = locations[0]
                        artifact = location.get('physicalLocation', {}).get('artifactLocation', {})
                        file_path = artifact.get('uri', 'go.mod')
                        region = location.get('physicalLocation', {}).get('region', {})
                        line = region.get('startLine', 0)
                    else:
                        file_path = 'go.mod'
                        line = 0

                    # Extract remediation from help text
                    help_text = result.get('message', {}).get('markdown', '')
                    remediation = self._extract_remediation(help_text, rule_id)

                    finding = Finding(
                        tool='govulncheck',
                        type='Dependency Vulnerability',
                        severity=severity,
                        file=self.normalize_path(file_path),
                        line=line,
                        rule=rule_id,
                        description=message,
                        remediation=remediation
                    )
                    findings.append(finding)

            self.mark_findings(len(findings))

        except Exception as e:
            self.handle_error(e, "", filepath)

        return findings, self.stats

    def _map_sarif_level(self, level: str) -> Severity:
        """Map SARIF level to Severity enum

        Args:
            level: SARIF level (error, warning, note, none)

        Returns:
            Severity enum value
        """
        level_map = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'note': Severity.LOW,
            'none': Severity.INFO
        }
        return level_map.get(level.lower(), Severity.INFO)

    def _extract_remediation(self, help_text: str, rule_id: str) -> str:
        """Extract remediation from SARIF help text

        Args:
            help_text: Markdown help text from SARIF
            rule_id: Vulnerability ID

        Returns:
            Remediation guidance
        """
        if 'upgrade' in help_text.lower() or 'update' in help_text.lower():
            # Extract version info if present
            return help_text.split('\n')[0] if help_text else f"Review {rule_id} and update affected dependency"
        return f"Review {rule_id} and update affected dependency"


class PipAuditParser(BaseParser):
    """Parser for pip-audit SARIF output"""

    def __init__(self):
        super().__init__("pip-audit")

    def parse_file(self, filepath: str) -> tuple[List[Finding], Dict[str, Any]]:
        """Parse pip-audit SARIF output

        Args:
            filepath: Path to pip-audit SARIF output file

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
                    # Map SARIF level to severity
                    level = result.get('level', 'warning')
                    severity = self._map_sarif_level(level)

                    rule_id = result.get('ruleId', 'UNKNOWN-VULN')
                    message = result.get('message', {}).get('text', 'Vulnerability in dependency')

                    # Extract location (usually requirements.txt or setup.py)
                    locations = result.get('locations') or []
                    if locations:
                        location = locations[0]
                        artifact = location.get('physicalLocation', {}).get('artifactLocation', {})
                        file_path = artifact.get('uri', 'requirements.txt')
                        region = location.get('physicalLocation', {}).get('region', {})
                        line = region.get('startLine', 0)
                    else:
                        file_path = 'requirements.txt'
                        line = 0

                    # Extract remediation from help text
                    help_text = result.get('message', {}).get('markdown', '')
                    remediation = self._extract_remediation(help_text, rule_id)

                    finding = Finding(
                        tool='pip-audit',
                        type='Dependency Vulnerability',
                        severity=severity,
                        file=self.normalize_path(file_path),
                        line=line,
                        rule=rule_id,
                        description=message,
                        remediation=remediation
                    )
                    findings.append(finding)

            self.mark_findings(len(findings))

        except Exception as e:
            self.handle_error(e, "", filepath)

        return findings, self.stats

    def _map_sarif_level(self, level: str) -> Severity:
        """Map SARIF level to Severity enum

        pip-audit typically uses 'warning' for all CVEs.
        We default to HIGH for security vulnerabilities.

        Args:
            level: SARIF level (error, warning, note, none)

        Returns:
            Severity enum value
        """
        level_map = {
            'error': Severity.HIGH,
            'warning': Severity.HIGH,  # Default to HIGH for CVEs
            'note': Severity.MEDIUM,
            'none': Severity.INFO
        }
        return level_map.get(level.lower(), Severity.HIGH)

    def _extract_remediation(self, help_text: str, rule_id: str) -> str:
        """Extract remediation from SARIF help text

        Args:
            help_text: Markdown help text from SARIF
            rule_id: Vulnerability ID

        Returns:
            Remediation guidance
        """
        if 'fix version' in help_text.lower() or 'upgrade' in help_text.lower():
            # Extract version info if present
            return help_text.split('\n')[0] if help_text else f"Update package to fix {rule_id}"
        return f"Update package to fix {rule_id}"
