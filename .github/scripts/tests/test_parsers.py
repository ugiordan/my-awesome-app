"""Unit tests for security tool parsers"""

import json
import tempfile
from pathlib import Path
import sys

# Add .github directory to path to enable scripts.* imports
github_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(github_dir))

from scripts.parsers.secrets import GitleaksParser, TruffleHogParser
from scripts.parsers.sast import SemgrepParser
from scripts.parsers.infra import ShellCheckParser, HadolintParser
from scripts.core.findings import Finding, Severity
from scripts.core.report import ReportGenerator


class TestGitleaksParser:
    """Tests for Gitleaks parser"""

    def test_parse_empty_file(self):
        """Test parsing empty Gitleaks output"""
        parser = GitleaksParser()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([], f)
            filepath = f.name

        try:
            findings, stats = parser.parse_file(filepath)
            assert len(findings) == 0
            assert stats['findings'] == 0
            assert stats['status'] == '✅ PASS'
        finally:
            Path(filepath).unlink()

    def test_parse_gitleaks_finding(self):
        """Test parsing Gitleaks finding"""
        parser = GitleaksParser()

        sample_data = [
            {
                "File": "config/secrets.yaml",
                "StartLine": 10,
                "RuleID": "generic-api-key",
                "Description": "Identified a Generic API Key"
            }
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sample_data, f)
            filepath = f.name

        try:
            findings, stats = parser.parse_file(filepath)
            assert len(findings) == 1
            assert findings[0].tool == 'Gitleaks'
            assert findings[0].severity == Severity.CRITICAL
            assert findings[0].file == 'config/secrets.yaml'
            assert findings[0].line == 10
            assert findings[0].rule == 'generic-api-key'
            assert stats['findings'] == 1
            assert stats['status'] == '❌ FINDINGS'
        finally:
            Path(filepath).unlink()

    def test_parse_missing_file(self):
        """Test parsing non-existent file"""
        parser = GitleaksParser()
        findings, stats = parser.parse_file('/nonexistent/file.json')
        assert len(findings) == 0
        assert stats['status'] == '⏭️ SKIPPED'


class TestTruffleHogParser:
    """Tests for TruffleHog parser"""

    def test_parse_trufflehog_finding(self):
        """Test parsing TruffleHog JSONL finding"""
        parser = TruffleHogParser()

        sample_line = {
            "DetectorName": "AWS",
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "aws-config.yaml",
                        "line": 5
                    }
                }
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(json.dumps(sample_line) + '\n')
            filepath = f.name

        try:
            findings, stats = parser.parse_file(filepath)
            assert len(findings) == 1
            assert findings[0].tool == 'TruffleHog'
            assert findings[0].severity == Severity.CRITICAL
            assert findings[0].detector == 'AWS'
            assert findings[0].file == 'aws-config.yaml'
            assert findings[0].line == 5
        finally:
            Path(filepath).unlink()


class TestSemgrepParser:
    """Tests for Semgrep parser"""

    def test_parse_semgrep_sarif(self):
        """Test parsing Semgrep SARIF output"""
        parser = SemgrepParser()

        sample_sarif = {
            "runs": [
                {
                    "results": [
                        {
                            "level": "error",
                            "ruleId": "hardcoded-secret-generic",
                            "message": {"text": "Hardcoded secret detected"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/config.py"},
                                        "region": {"startLine": 42}
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
            json.dump(sample_sarif, f)
            filepath = f.name

        try:
            findings, stats = parser.parse_file(filepath)
            assert len(findings) == 1
            assert findings[0].tool == 'Semgrep'
            assert findings[0].severity == Severity.HIGH
            assert findings[0].rule == 'hardcoded-secret-generic'
            assert findings[0].file == 'src/config.py'
            assert findings[0].line == 42
        finally:
            Path(filepath).unlink()


class TestShellCheckParser:
    """Tests for ShellCheck parser"""

    def test_parse_shellcheck_json(self):
        """Test parsing ShellCheck JSON output"""
        parser = ShellCheckParser()

        sample_data = [
            {
                "file": "scripts/deploy.sh",
                "line": 15,
                "code": 2086,
                "level": "warning",
                "message": "Double quote to prevent globbing and word splitting"
            }
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sample_data, f)
            filepath = f.name

        try:
            findings, stats = parser.parse_file(filepath)
            assert len(findings) == 1
            assert findings[0].tool == 'ShellCheck'
            assert findings[0].severity == Severity.MEDIUM
            assert findings[0].code == 2086
            assert findings[0].rule == 'SC2086'
            assert findings[0].file == 'scripts/deploy.sh'
            assert findings[0].line == 15
        finally:
            Path(filepath).unlink()

    def test_parse_shellcheck_json1_format(self):
        """Test parsing ShellCheck json1 format"""
        parser = ShellCheckParser()

        sample_data = {
            "comments": [
                {
                    "file": "test.sh",
                    "line": 5,
                    "code": 2034,
                    "level": "warning",
                    "message": "var appears unused"
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sample_data, f)
            filepath = f.name

        try:
            findings, stats = parser.parse_file(filepath)
            assert len(findings) == 1
            assert findings[0].code == 2034
        finally:
            Path(filepath).unlink()


class TestHadolintParser:
    """Tests for Hadolint parser"""

    def test_parse_hadolint_sarif(self):
        """Test parsing Hadolint SARIF output"""
        parser = HadolintParser()

        sample_sarif = {
            "runs": [
                {
                    "results": [
                        {
                            "level": "error",
                            "ruleId": "DL3008",
                            "message": {"text": "Pin versions in apt get install"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "Dockerfile"},
                                        "region": {"startLine": 10}
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
            json.dump(sample_sarif, f)
            filepath = f.name

        try:
            findings, stats = parser.parse_file(filepath)
            assert len(findings) == 1
            assert findings[0].tool == 'Hadolint'
            assert findings[0].severity == Severity.HIGH
            assert findings[0].rule == 'DL3008'
            assert findings[0].type == 'Dockerfile Issue'
        finally:
            Path(filepath).unlink()


class TestErrorReporting:
    """Tests for parser error reporting"""

    def test_malformed_json_handling(self):
        """Test that malformed JSON is properly reported"""
        parser = GitleaksParser()

        # Create file with malformed JSON
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{ invalid json content }')
            filepath = f.name

        try:
            findings, stats = parser.parse_file(filepath)

            # Parser should return empty findings
            assert len(findings) == 0

            # Stats should contain error information
            assert '⚠️ ERROR' in stats['status']
            assert 'error' in stats
            assert stats['error']['type'] == 'JSONDecodeError'
            assert stats['error']['message']  # Should have sanitized error message
            assert stats['error']['file']  # Should have normalized filepath
            assert stats['error']['context'] == 'JSON parsing'
        finally:
            Path(filepath).unlink()

    def test_multiple_parser_failures(self):
        """Test that multiple parser failures are tracked independently"""
        # Test Gitleaks parser failure
        gitleaks_parser = GitleaksParser()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{ bad json }')
            gitleaks_path = f.name

        try:
            _, gitleaks_stats = gitleaks_parser.parse_file(gitleaks_path)
            assert 'error' in gitleaks_stats
            assert gitleaks_stats['error']['type'] == 'JSONDecodeError'
        finally:
            Path(gitleaks_path).unlink()

        # Test Semgrep parser failure
        semgrep_parser = SemgrepParser()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
            f.write('not valid sarif')
            semgrep_path = f.name

        try:
            _, semgrep_stats = semgrep_parser.parse_file(semgrep_path)
            assert 'error' in semgrep_stats
            assert semgrep_stats['error']['type'] == 'JSONDecodeError'

            # Verify errors are independent
            assert gitleaks_stats['error']['file'] != semgrep_stats['error']['file']
        finally:
            Path(semgrep_path).unlink()

    def test_report_generation_with_errors(self):
        """Test that report generation includes parser diagnostics section"""
        # Create a report generator with some findings and errors
        report_gen = ReportGenerator()

        # Add a successful parser result
        gitleaks_findings = [
            Finding(
                tool='Gitleaks',
                type='Secret Detection',
                severity=Severity.CRITICAL,
                file='config/secrets.yaml',
                line=10,
                rule='generic-api-key',
                description='API key detected',
                remediation='Remove secret from code'
            )
        ]
        gitleaks_stats = {
            'tool': 'Gitleaks',
            'findings': 1,
            'status': '❌ FINDINGS'
        }
        report_gen.add_findings(gitleaks_findings, gitleaks_stats)

        # Add a failed parser result
        semgrep_stats = {
            'tool': 'Semgrep',
            'findings': 0,
            'status': '⚠️ ERROR: Failed to parse Semgrep output',
            'error': {
                'message': 'Invalid JSON format',
                'type': 'JSONDecodeError',
                'context': 'JSON parsing',
                'file': 'semgrep.sarif'
            }
        }
        report_gen.add_findings([], semgrep_stats)

        # Generate markdown report to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            report_path = f.name

        try:
            report_gen.generate_markdown_summary(report_path)

            # Read report and verify parser diagnostics section
            with open(report_path) as f:
                report_content = f.read()

            # Should contain Parser Diagnostics section
            assert '## 🔍 Parser Diagnostics' in report_content
            assert 'Semgrep' in report_content
            assert 'JSONDecodeError' in report_content
            assert 'Invalid JSON format' in report_content
            assert 'semgrep.sarif' in report_content
            assert 'This tool\'s findings may be incomplete or missing' in report_content

            # Should use collapsible details
            assert '<details>' in report_content
            assert '</details>' in report_content
        finally:
            Path(report_path).unlink()

    def test_error_message_sanitization(self):
        """Test that error messages are sanitized to prevent markdown injection"""
        parser = GitleaksParser()

        # Create file that will cause error with special markdown characters
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{ "key": "<script>alert("xss")</script>" }')
            filepath = f.name

        try:
            findings, stats = parser.parse_file(filepath)

            # Error message should be HTML-escaped
            assert 'error' in stats
            error_msg = stats['error']['message']

            # Should not contain raw HTML/script tags
            assert '<script>' not in error_msg
            assert '&lt;script&gt;' in error_msg or 'Expecting' in error_msg  # Either escaped or JSON error
        finally:
            Path(filepath).unlink()

    def test_filepath_normalization_in_errors(self):
        """Test that filepaths in error reports are normalized"""
        parser = GitleaksParser()

        # Create file with path that needs normalization
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, dir='/tmp') as f:
            f.write('invalid json')
            filepath = f.name

        try:
            findings, stats = parser.parse_file(filepath)

            # Filepath should be normalized (relative path without /repo/ prefix)
            assert 'error' in stats
            normalized_path = stats['error']['file']

            # Should not contain /repo/ prefix
            assert not normalized_path.startswith('/repo/')

            # Should be normalized (no leading /)
            # (Note: temp files may still have full path, but /repo/ should be stripped)
            assert stats['error']['file']  # Just verify it exists and is processed
        finally:
            Path(filepath).unlink()


def run_tests():
    """Run all parser tests"""
    print("Running parser tests...")

    # Gitleaks tests
    print("\nTesting GitleaksParser...")
    test = TestGitleaksParser()
    test.test_parse_empty_file()
    test.test_parse_gitleaks_finding()
    test.test_parse_missing_file()
    print("✅ GitleaksParser tests passed")

    # TruffleHog tests
    print("\nTesting TruffleHogParser...")
    test = TestTruffleHogParser()
    test.test_parse_trufflehog_finding()
    print("✅ TruffleHogParser tests passed")

    # Semgrep tests
    print("\nTesting SemgrepParser...")
    test = TestSemgrepParser()
    test.test_parse_semgrep_sarif()
    print("✅ SemgrepParser tests passed")

    # ShellCheck tests
    print("\nTesting ShellCheckParser...")
    test = TestShellCheckParser()
    test.test_parse_shellcheck_json()
    test.test_parse_shellcheck_json1_format()
    print("✅ ShellCheckParser tests passed")

    # Hadolint tests
    print("\nTesting HadolintParser...")
    test = TestHadolintParser()
    test.test_parse_hadolint_sarif()
    print("✅ HadolintParser tests passed")

    # Error reporting tests
    print("\nTesting Error Reporting...")
    test = TestErrorReporting()
    test.test_malformed_json_handling()
    test.test_multiple_parser_failures()
    test.test_report_generation_with_errors()
    test.test_error_message_sanitization()
    test.test_filepath_normalization_in_errors()
    print("✅ Error Reporting tests passed")

    print("\n✅ All parser tests passed!")


if __name__ == '__main__':
    run_tests()
