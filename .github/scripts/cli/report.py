#!/usr/bin/env python3
"""CLI for generating security reports using modular parsers

Backward compatible with legacy generate-security-report.py interface.
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Dict

# Ensure package imports work
scripts_dir = Path(__file__).resolve().parent.parent
github_dir = scripts_dir.parent
if str(github_dir) not in sys.path:
    sys.path.insert(0, str(github_dir))
if str(scripts_dir) not in sys.path:
    sys.path.insert(0, str(scripts_dir))

from scripts.core.baseline import BaselineManager
from scripts.core.report import ReportGenerator
from scripts.parsers import (
    GitleaksParser,
    TruffleHogParser,
    SemgrepParser,
    HadolintParser,
    ShellCheckParser,
    YamllintParser,
    ActionlintParser,
    KubeLinterParser,
    RBACAnalyzerParser,
    GovulncheckParser,
    PipAuditParser,
)


def main():
    """Main entry point for report generation CLI"""
    parser = argparse.ArgumentParser(description='Generate comprehensive security scan report')
    parser.add_argument('--output', default='security-report.md', help='Output file path')
    parser.add_argument('--json-summary', default=None, help='JSON summary output file for workflow parsing')
    parser.add_argument('--yamllint-report', default=None, help='Dedicated yamllint report output file (all findings)')
    parser.add_argument('--workspace', default='.', help='Workspace directory')
    parser.add_argument('--yamllint-limit', type=int, default=50, help='Maximum yamllint findings to show in comprehensive report (default: 50)')

    args = parser.parse_args()

    # Gather GitHub context from environment (same as legacy script)
    server_url = os.getenv('GITHUB_SERVER_URL', '')
    repository = os.getenv('GITHUB_REPOSITORY', '')
    run_id = os.getenv('GITHUB_RUN_ID', '')

    if server_url and repository and run_id:
        run_url = f"{server_url}/{repository}/actions/runs/{run_id}"
    else:
        run_url = 'N/A'

    github_context = {
        'repository': repository or 'unknown',
        'sha': os.getenv('GITHUB_SHA', 'unknown'),
        'ref_name': os.getenv('GITHUB_REF_NAME', 'unknown'),
        'run_url': run_url
    }

    # Initialize baseline manager
    baseline = BaselineManager()
    try:
        baseline.load_from_env()
    except SystemExit:
        print("[ERROR] Failed to load baseline", file=sys.stderr)
        return 1

    # Initialize report generator
    report = ReportGenerator(github_context)

    # Initialize all parsers
    parsers = {
        'gitleaks': GitleaksParser(),
        'trufflehog': TruffleHogParser(),
        'semgrep': SemgrepParser(),
        'hadolint': HadolintParser(),
        'shellcheck': ShellCheckParser(),
        'yamllint': YamllintParser(max_findings=args.yamllint_limit),
        'actionlint': ActionlintParser(),
        'kube-linter': KubeLinterParser(),
        'rbac-analyzer': RBACAnalyzerParser(),
        'govulncheck': GovulncheckParser(),
        'pip-audit': PipAuditParser(),
    }

    # Parse all tool outputs
    workspace = Path(args.workspace)
    tool_files = {
        'gitleaks': workspace / 'gitleaks.json',
        'trufflehog': workspace / 'trufflehog.json',
        'semgrep': workspace / 'semgrep.sarif',
        'hadolint': workspace / 'hadolint.sarif',
        'shellcheck': workspace / 'shellcheck.json',
        'yamllint': workspace / 'yamllint.txt',
        'actionlint': workspace / 'actionlint.txt',
        'kube-linter': workspace / 'kube-linter.json',
        'rbac-analyzer': workspace / 'rbac-analysis.md',
        'govulncheck': workspace / 'govulncheck.sarif',
        'pip-audit': workspace / 'pip-audit.sarif',
    }

    for tool_name, parser in parsers.items():
        tool_file = str(tool_files[tool_name])
        print(f"[INFO] Parsing {tool_name} output: {tool_file}", file=sys.stderr)

        # Parse findings
        findings, stats = parser.parse_file(tool_file)

        # Filter acknowledged findings
        filtered_findings = []
        for finding in findings:
            finding_dict = finding.to_dict()
            if not baseline.is_acknowledged(tool_name, finding_dict):
                filtered_findings.append(finding)
            else:
                baseline.mark_acknowledged(tool_name)

        # Update stats with filtered count
        stats['findings'] = len(filtered_findings)
        if len(filtered_findings) > 0:
            stats['status'] = '❌ FINDINGS'
        elif stats['status'] == '❌ FINDINGS':
            stats['status'] = '✅ PASS'

        # Add to report
        report.add_findings(filtered_findings, stats)

    # Generate markdown report
    print(f"[INFO] Generating markdown report: {args.output}", file=sys.stderr)
    report.generate_markdown_summary(args.output)

    # Generate JSON summary if requested
    if args.json_summary:
        print(f"[INFO] Generating JSON summary: {args.json_summary}", file=sys.stderr)
        report.generate_json_summary(args.json_summary)

    # Generate dedicated yamllint report if requested
    if args.yamllint_report:
        print(f"[INFO] Generating dedicated yamllint report: {args.yamllint_report}", file=sys.stderr)
        # Extract yamllint findings from all severities
        yamllint_findings = []
        for severity_findings in report.findings.values():
            yamllint_findings.extend([f for f in severity_findings if f.tool == 'yamllint'])

        with open(args.yamllint_report, 'w') as f:
            f.write("# yamllint Findings\n\n")
            if not yamllint_findings:
                f.write("No yamllint findings.\n")
            else:
                for finding in yamllint_findings:
                    f.write(f"- **{finding.file}:{finding.line}** - {finding.description}\n")

    # Print success messages (matches legacy script)
    print(f"✅ Comprehensive security report generated: {args.output}")
    if args.json_summary:
        print(f"✅ JSON summary generated: {args.json_summary}")
    if args.yamllint_report:
        print(f"✅ Dedicated yamllint report generated: {args.yamllint_report}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
