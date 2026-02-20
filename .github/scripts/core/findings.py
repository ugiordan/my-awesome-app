"""Finding data models for security scanning tools"""

from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, Union
from enum import Enum


class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_string(cls, severity_str: str) -> 'Severity':
        """Convert string to Severity enum"""
        severity_str = severity_str.upper()
        for severity in cls:
            if severity.value == severity_str:
                return severity
        return cls.INFO  # Default to INFO if unknown


@dataclass
class Finding:
    """Represents a security finding from any tool

    Core fields (required for all tools):
        tool: Name of the security tool (Gitleaks, Semgrep, etc.)
        type: Finding type/category
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        file: File path where finding was detected
        line: Line number (can be string for special cases like kube-linter)
        rule: Rule ID or check name
        description: Human-readable description
        remediation: How to fix the finding

    Tool-specific fields (optional):
        check: kube-linter check name
        detector: TruffleHog detector name
        code: ShellCheck code number
        title: RBAC Analyzer finding title
        verified: TruffleHog verification status
    """
    tool: str
    type: str
    severity: Severity
    file: str
    line: Union[int, str]
    rule: str
    description: str
    remediation: str

    # Tool-specific optional fields
    check: Optional[str] = None  # kube-linter
    detector: Optional[str] = None  # TruffleHog
    code: Optional[int] = None  # ShellCheck
    title: Optional[str] = None  # RBAC Analyzer
    verified: Optional[bool] = None  # TruffleHog

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for backward compatibility

        Returns:
            Dictionary with severity converted to string
        """
        data = asdict(self)
        data['severity'] = self.severity.value
        # Remove None values to keep dict clean
        return {k: v for k, v in data.items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create Finding from dictionary

        Args:
            data: Dictionary containing finding data

        Returns:
            Finding instance
        """
        # Convert severity string to Severity enum
        if isinstance(data.get('severity'), str):
            data['severity'] = Severity.from_string(data['severity'])

        # Filter to only include fields defined in the dataclass
        valid_fields = {f for f in cls.__dataclass_fields__}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}

        return cls(**filtered_data)

    def calculate_risk_score(self) -> int:
        """Calculate 0-100 risk score based on severity

        Returns:
            Risk score (0-100)
        """
        severity_scores = {
            Severity.CRITICAL: 100,
            Severity.HIGH: 75,
            Severity.MEDIUM: 50,
            Severity.LOW: 25,
            Severity.INFO: 10
        }
        return severity_scores.get(self.severity, 0)

    def get_baseline_key(self) -> str:
        """Generate unique key for baseline matching

        Different tools use different matching strategies:
        - Gitleaks: file:line:rule
        - TruffleHog: file:detector
        - Semgrep: file:line:rule
        - ShellCheck: file:line:code
        - kube-linter: check:file (file is actually object ID)
        - RBAC Analyzer: file:title

        Returns:
            String key for baseline matching
        """
        if self.tool == 'TruffleHog':
            return f"{self.file}:{self.detector}"
        elif self.tool == 'ShellCheck' and self.code:
            return f"{self.file}:{self.line}:{self.code}"
        elif self.tool == 'kube-linter' and self.check:
            return f"{self.check}:{self.file}"
        elif self.tool == 'RBAC Analyzer' and self.title:
            return f"{self.file}:{self.title}"
        else:
            # Default: file:line:rule
            return f"{self.file}:{self.line}:{self.rule}"
