"""Parser for Kubernetes manifest scanner (kube-linter)"""

from typing import List, Dict, Any

from scripts.parsers.base import BaseParser
from scripts.core.findings import Finding, Severity


class KubeLinterParser(BaseParser):
    """Parser for kube-linter JSON output"""

    def __init__(self):
        super().__init__("kube-linter")

        # Severity mapping for kube-linter checks
        # Critical: Active privilege escalation, container escape, cluster-admin access
        self.critical_checks = {
            'cluster-admin-role-binding', 'privileged-container',
            'host-network', 'host-pid', 'host-ipc', 'docker-sock',
            'access-to-create-pods', 'privilege-escalation-container'
        }

        # High: RBAC wildcards, secret access, sensitive mounts
        self.high_checks = {
            'access-to-secrets', 'wildcard-in-rules', 'sensitive-host-mounts',
            'writable-host-mount', 'unsafe-proc-mount', 'unsafe-sysctls',
            'default-service-account', 'env-var-secret', 'read-secret-from-env-var',
            'drop-net-raw-capability', 'exposed-services', 'non-isolated-pod',
            'ssh-port', 'latest-tag', 'no-system-group-binding'
        }

        # Medium: Security best practices (missing configs, hardening)
        self.medium_checks = {
            'no-liveness-probe', 'no-readiness-probe',
            'unset-cpu-requirements', 'unset-memory-requirements',
            'use-namespace', 'non-existent-service-account',
            'run-as-non-root', 'no-read-only-root-fs', 'privileged-ports'
        }

    def parse_file(self, filepath: str) -> tuple[List[Finding], Dict[str, Any]]:
        """Parse kube-linter JSON output

        kube-linter v0.7.6+ JSON format:
        {
          "Reports": [
            {
              "Object": {
                "K8sObject": {
                  "Namespace": "...",
                  "Name": "...",
                  "GroupVersionKind": {...}
                }
              },
              "Check": "check-name",
              "Diagnostic": {
                "Message": "...",
                "Description": "..."
              }
            }
          ]
        }

        Args:
            filepath: Path to kube-linter JSON output file

        Returns:
            Tuple of (findings_list, stats_dict)
        """
        data = self.load_json_file(filepath)
        if data is None:
            return [], self.stats

        findings = []

        try:
            reports = data.get('Reports', [])
            if not reports:
                return [], self.stats

            # Deduplicate findings by check:object:message combination
            seen = set()

            for report in reports:
                check_name = report.get('Check', 'unknown')
                diagnostic = report.get('Diagnostic', {})
                message = diagnostic.get('Message', 'kube-linter finding')
                description = diagnostic.get('Description', '')

                # Extract object information
                # kube-linter v0.7.6+ structure has K8sObjectInfo fields under Object.K8sObject
                obj = report.get('Object', {}).get('K8sObject', {})
                namespace = obj.get('Namespace', '')
                name = obj.get('Name', 'unknown')
                gvk = obj.get('GroupVersionKind', {})
                kind = gvk.get('Kind', 'unknown')

                # Construct object identifier
                if namespace:
                    object_id = f"{kind}/{namespace}/{name}"
                else:
                    object_id = f"{kind}/{name}"

                # Deduplication key
                dedup_key = f"{check_name}:{object_id}:{message}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Map check severity
                if check_name in self.critical_checks:
                    severity = Severity.CRITICAL
                elif check_name in self.high_checks:
                    severity = Severity.HIGH
                elif check_name in self.medium_checks:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW

                finding = Finding(
                    tool='kube-linter',
                    type='Kubernetes Manifest Security',
                    severity=severity,
                    file=object_id,  # Use object ID as "file" for display
                    line=check_name,  # Use check name as "line" for display
                    rule=check_name,
                    description=f"{message} (Object: {object_id})",
                    remediation=description or 'Fix Kubernetes manifest according to check requirements',
                    check=check_name  # For baseline matching
                )

                # Store object metadata for baseline matching (convert to dict to add fields)
                finding_dict = finding.to_dict()
                finding_dict['object_kind'] = kind
                finding_dict['object_name'] = name
                finding_dict['object_namespace'] = namespace or None

                # Create new Finding with extra fields
                finding = Finding.from_dict(finding_dict)
                findings.append(finding)

            self.mark_findings(len(findings))

        except Exception as e:
            self.handle_error(e, "", filepath)

        return findings, self.stats
