"""Parser for SAST tools (Semgrep)"""

from typing import List, Dict, Any

from scripts.parsers.base import BaseParser
from scripts.core.findings import Finding, Severity


class SemgrepParser(BaseParser):
    """Parser for Semgrep SARIF output"""

    def __init__(self):
        super().__init__("Semgrep")

    def parse_file(self, filepath: str) -> tuple[List[Finding], Dict[str, Any]]:
        """Parse Semgrep SARIF output

        Args:
            filepath: Path to Semgrep SARIF output file

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
                        'note': Severity.INFO
                    }
                    severity = severity_map.get(level, Severity.INFO)

                    rule = result.get('ruleId', 'unknown')
                    message = result.get('message', {}).get('text', 'No description')

                    locations = result.get('locations') or []
                    location = locations[0] if locations else {}
                    artifact = location.get('physicalLocation', {}).get('artifactLocation', {})
                    file_path = artifact.get('uri', 'unknown')

                    region = location.get('physicalLocation', {}).get('region', {})
                    line = region.get('startLine', '?')

                    finding = Finding(
                        tool='Semgrep',
                        type=rule,
                        severity=severity,
                        file=file_path,
                        line=line,
                        rule=rule,
                        description=message,
                        remediation=self._get_remediation(rule)
                    )
                    findings.append(finding)

            self.mark_findings(len(findings))

        except Exception as e:
            self.handle_error(e, "", filepath)

        return findings, self.stats

    def _get_remediation(self, rule_id: str) -> str:
        """Get remediation guidance for Semgrep rules

        Args:
            rule_id: Semgrep rule identifier

        Returns:
            Remediation guidance string
        """
        remediations = {
            'hardcoded-secret-generic': 'Remove hardcoded secret, use environment variables or secret manager',
            'rbac-wildcard-resources': 'Replace wildcard with specific resources following least privilege',
            'rbac-wildcard-verbs': 'Replace wildcard with specific verbs needed for operation',
            'rbac-dangerous-verbs': 'Remove dangerous verbs (escalate/impersonate/bind) or justify usage',
            'insecure-tls-skip-verify': 'Remove InsecureSkipVerify, properly configure certificate validation',
            'weak-crypto-md5': 'Replace MD5 with SHA-256 or stronger hash function',
            'weak-crypto-sha1': 'Replace SHA-1 with SHA-256 or stronger hash function',
            'operator-privileged-pod': 'Remove privileged: true, use specific capabilities if needed',
        }
        return remediations.get(rule_id, 'Follow security best practices for this finding')
