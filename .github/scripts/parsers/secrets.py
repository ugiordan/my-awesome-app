"""Parsers for secret scanning tools (Gitleaks, TruffleHog)"""

import json
import hashlib
from typing import List, Dict, Any

from scripts.parsers.base import BaseParser
from scripts.core.findings import Finding, Severity


class GitleaksParser(BaseParser):
    """Parser for Gitleaks JSON output"""

    def __init__(self):
        super().__init__("Gitleaks")

    def parse_file(self, filepath: str) -> tuple[List[Finding], Dict[str, Any]]:
        """Parse Gitleaks JSON output

        Args:
            filepath: Path to Gitleaks JSON output file

        Returns:
            Tuple of (findings_list, stats_dict)
        """
        data = self.load_json_file(filepath)
        if data is None:
            return [], self.stats

        findings = []

        try:
            if data:
                # Deduplicate findings by file:line:rule:description_hash combination
                seen = set()

                for finding_data in data:
                    # Normalize file path
                    file_path = self.normalize_path(finding_data.get('File', 'unknown'))

                    # Include description hash to differentiate multiple secrets at same location
                    description = finding_data.get('Description', 'Secret detected')
                    desc_hash = hashlib.sha256(description.encode()).hexdigest()[:8]
                    dedup_key = f"{file_path}:{finding_data.get('StartLine', '?')}:{finding_data.get('RuleID', 'unknown')}:{desc_hash}"

                    if dedup_key not in seen:
                        seen.add(dedup_key)

                        finding = Finding(
                            tool='Gitleaks',
                            type='Hardcoded Secret',
                            severity=Severity.CRITICAL,
                            file=file_path,
                            line=finding_data.get('StartLine', '?'),
                            rule=finding_data.get('RuleID', 'unknown'),
                            description=finding_data.get(
                                'Description',
                                'Secret detected; see Gitleaks JSON artifact for details (value redacted)'
                            ),
                            remediation='Remove secret from code, rotate credential, use secret manager'
                        )
                        findings.append(finding)

            self.mark_findings(len(findings))

        except Exception as e:
            self.handle_error(e, "", filepath)

        return findings, self.stats


class TruffleHogParser(BaseParser):
    """Parser for TruffleHog JSON output (JSONL format)"""

    def __init__(self):
        super().__init__("TruffleHog")

    def parse_file(self, filepath: str) -> tuple[List[Finding], Dict[str, Any]]:
        """Parse TruffleHog JSONL output

        Args:
            filepath: Path to TruffleHog JSONL output file

        Returns:
            Tuple of (findings_list, stats_dict)
        """
        lines = self.load_text_file(filepath)
        if lines is None:
            return [], self.stats

        findings = []
        parse_errors = 0

        try:
            for line in lines:
                if not line.strip():
                    continue

                try:
                    finding_data = json.loads(line)
                except json.JSONDecodeError:
                    parse_errors += 1
                    continue

                # Extract file and line from nested structure
                fs_data = finding_data.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {})
                file_path = self.normalize_path(fs_data.get('file', 'unknown'))
                line_num = fs_data.get('line', 0)
                detector = finding_data.get('DetectorName', 'unknown')

                finding = Finding(
                    tool='TruffleHog',
                    type='Verified Credential',
                    severity=Severity.CRITICAL,
                    file=file_path,
                    line=line_num,  # Preserve numeric value for baseline matching (0, not '?')
                    rule=detector,
                    description=f"Verified {detector} found",
                    remediation='URGENT: Rotate this credential immediately - it has been verified as active',
                    detector=detector,  # For baseline matching
                    verified=True
                )
                findings.append(finding)

            self.mark_findings(len(findings))

            # Update status if there were parse errors
            if parse_errors > 0:
                if len(findings) > 0:
                    self.stats['status'] = f"❌ FINDINGS (partial: {parse_errors} unparsable lines)"
                else:
                    self.stats['status'] = f"⚠️ PARTIAL: {parse_errors} unparsable lines"

        except Exception as e:
            self.handle_error(e, "", filepath)

        return findings, self.stats
