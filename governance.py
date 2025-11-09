#!/usr/bin/env python3
"""
Governance Module for Ajeer Automation
Provides policy enforcement, compliance tracking, and audit trails
"""

import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum


class PolicyType(Enum):
    """Types of policies"""
    RATE_LIMIT = "rate_limit"
    FILE_SIZE = "file_size"
    FILE_TYPE = "file_type"
    WORKING_HOURS = "working_hours"
    USER_ACCESS = "user_access"
    DATA_RETENTION = "data_retention"
    APPROVAL_REQUIRED = "approval_required"


class PolicySeverity(Enum):
    """Policy violation severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Policy:
    """Represents a governance policy"""
    id: str
    name: str
    type: PolicyType
    enabled: bool
    rules: Dict[str, Any]
    severity: PolicySeverity
    description: str
    created_at: str
    updated_at: str
    enforce: bool = True  # If False, only logs violations


@dataclass
class PolicyViolation:
    """Represents a policy violation"""
    policy_id: str
    policy_name: str
    severity: PolicySeverity
    message: str
    context: Dict[str, Any]
    timestamp: str
    user: str = "system"
    action_taken: str = "blocked"


@dataclass
class ComplianceReport:
    """Compliance report"""
    report_id: str
    generated_at: str
    period_start: str
    period_end: str
    total_operations: int
    violations: List[PolicyViolation]
    policies_checked: List[str]
    compliance_score: float  # 0-100


class PolicyEngine:
    """
    Policy enforcement engine
    """

    def __init__(self, config_path: Path = Path('config/policies.json')):
        self.config_path = config_path
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        self.policies: Dict[str, Policy] = {}
        self.violations: List[PolicyViolation] = []
        self.violation_log = Path('state/policy_violations.jsonl')
        self.violation_log.parent.mkdir(parents=True, exist_ok=True)

        self.load_policies()
        self._setup_default_policies()

    def _setup_default_policies(self):
        """Setup default policies if none exist"""
        if not self.policies:
            defaults = [
                Policy(
                    id="rate_limit_daily",
                    name="Daily Submission Rate Limit",
                    type=PolicyType.RATE_LIMIT,
                    enabled=True,
                    rules={
                        "max_per_day": 100,
                        "max_per_hour": 20,
                        "min_delay_seconds": 5
                    },
                    severity=PolicySeverity.HIGH,
                    description="Limit submissions to prevent system overload",
                    created_at=datetime.now().isoformat(),
                    updated_at=datetime.now().isoformat(),
                    enforce=True
                ),
                Policy(
                    id="file_size_limit",
                    name="Maximum File Size",
                    type=PolicyType.FILE_SIZE,
                    enabled=True,
                    rules={
                        "max_size_mb": 50,
                        "warn_size_mb": 25
                    },
                    severity=PolicySeverity.MEDIUM,
                    description="Limit PDF file sizes",
                    created_at=datetime.now().isoformat(),
                    updated_at=datetime.now().isoformat(),
                    enforce=True
                ),
                Policy(
                    id="working_hours",
                    name="Working Hours Restriction",
                    type=PolicyType.WORKING_HOURS,
                    enabled=False,  # Disabled by default
                    rules={
                        "start_hour": 8,  # 8 AM
                        "end_hour": 18,   # 6 PM
                        "weekdays_only": True,
                        "timezone": "local"
                    },
                    severity=PolicySeverity.LOW,
                    description="Only allow processing during business hours",
                    created_at=datetime.now().isoformat(),
                    updated_at=datetime.now().isoformat(),
                    enforce=False
                ),
                Policy(
                    id="data_retention",
                    name="Data Retention Policy",
                    type=PolicyType.DATA_RETENTION,
                    enabled=True,
                    rules={
                        "processed_days": 90,
                        "failed_days": 180,
                        "logs_days": 365,
                        "audit_days": 2555  # 7 years
                    },
                    severity=PolicySeverity.MEDIUM,
                    description="Auto-delete old files per retention policy",
                    created_at=datetime.now().isoformat(),
                    updated_at=datetime.now().isoformat(),
                    enforce=True
                ),
                Policy(
                    id="approval_required_high_volume",
                    name="Approval Required for High Volume",
                    type=PolicyType.APPROVAL_REQUIRED,
                    enabled=False,
                    rules={
                        "threshold": 50,
                        "approval_timeout_minutes": 30
                    },
                    severity=PolicySeverity.MEDIUM,
                    description="Require approval for batches over threshold",
                    created_at=datetime.now().isoformat(),
                    updated_at=datetime.now().isoformat(),
                    enforce=False
                )
            ]

            for policy in defaults:
                self.policies[policy.id] = policy

            self.save_policies()

    def load_policies(self):
        """Load policies from config file"""
        if not self.config_path.exists():
            return

        try:
            with open(self.config_path, 'r') as f:
                data = json.load(f)

            for policy_data in data.get('policies', []):
                policy_data['type'] = PolicyType(policy_data['type'])
                policy_data['severity'] = PolicySeverity(policy_data['severity'])
                policy = Policy(**policy_data)
                self.policies[policy.id] = policy
        except Exception:
            pass

    def save_policies(self):
        """Save policies to config file"""
        data = {
            'policies': [
                {
                    **asdict(policy),
                    'type': policy.type.value,
                    'severity': policy.severity.value
                }
                for policy in self.policies.values()
            ]
        }

        with open(self.config_path, 'w') as f:
            json.dump(data, f, indent=2)

    def check_policy(
        self,
        policy_id: str,
        context: Dict[str, Any]
    ) -> Optional[PolicyViolation]:
        """
        Check if a policy is violated

        Returns:
            PolicyViolation if violated, None if compliant
        """
        policy = self.policies.get(policy_id)
        if not policy or not policy.enabled:
            return None

        # Check based on policy type
        checker = {
            PolicyType.RATE_LIMIT: self._check_rate_limit,
            PolicyType.FILE_SIZE: self._check_file_size,
            PolicyType.WORKING_HOURS: self._check_working_hours,
            PolicyType.APPROVAL_REQUIRED: self._check_approval_required
        }.get(policy.type)

        if not checker:
            return None

        violation_message = checker(policy, context)
        if violation_message:
            violation = PolicyViolation(
                policy_id=policy.id,
                policy_name=policy.name,
                severity=policy.severity,
                message=violation_message,
                context=context,
                timestamp=datetime.now().isoformat(),
                user=context.get('user', 'system'),
                action_taken='blocked' if policy.enforce else 'logged'
            )

            self.log_violation(violation)
            return violation

        return None

    def _check_rate_limit(self, policy: Policy, context: Dict[str, Any]) -> Optional[str]:
        """Check rate limit policy"""
        current_count = context.get('current_count', 0)
        max_allowed = policy.rules.get('max_per_day', 100)

        if current_count >= max_allowed:
            return f"Daily limit exceeded: {current_count}/{max_allowed}"

        # Check hourly limit
        hourly_count = context.get('hourly_count', 0)
        max_hourly = policy.rules.get('max_per_hour', 20)

        if hourly_count >= max_hourly:
            return f"Hourly limit exceeded: {hourly_count}/{max_hourly}"

        return None

    def _check_file_size(self, policy: Policy, context: Dict[str, Any]) -> Optional[str]:
        """Check file size policy"""
        file_size_mb = context.get('file_size_mb', 0)
        max_size = policy.rules.get('max_size_mb', 50)

        if file_size_mb > max_size:
            return f"File too large: {file_size_mb:.1f}MB > {max_size}MB"

        return None

    def _check_working_hours(self, policy: Policy, context: Dict[str, Any]) -> Optional[str]:
        """Check working hours policy"""
        now = datetime.now()

        # Check weekday
        if policy.rules.get('weekdays_only') and now.weekday() >= 5:  # Sat/Sun
            return f"Operation not allowed on weekends"

        # Check hours
        start_hour = policy.rules.get('start_hour', 8)
        end_hour = policy.rules.get('end_hour', 18)

        if now.hour < start_hour or now.hour >= end_hour:
            return f"Operation outside working hours ({start_hour}:00-{end_hour}:00)"

        return None

    def _check_approval_required(self, policy: Policy, context: Dict[str, Any]) -> Optional[str]:
        """Check if approval is required"""
        batch_size = context.get('batch_size', 0)
        threshold = policy.rules.get('threshold', 50)
        approved = context.get('approved', False)

        if batch_size >= threshold and not approved:
            return f"Approval required for batch of {batch_size} (threshold: {threshold})"

        return None

    def check_all_policies(self, context: Dict[str, Any]) -> List[PolicyViolation]:
        """Check all enabled policies"""
        violations = []

        for policy in self.policies.values():
            if not policy.enabled:
                continue

            violation = self.check_policy(policy.id, context)
            if violation:
                violations.append(violation)

        return violations

    def log_violation(self, violation: PolicyViolation):
        """Log a policy violation"""
        self.violations.append(violation)

        # Write to violation log
        with open(self.violation_log, 'a') as f:
            f.write(json.dumps(asdict(violation)) + '\n')

    def get_violations(
        self,
        hours: int = 24,
        severity: Optional[PolicySeverity] = None
    ) -> List[PolicyViolation]:
        """Get recent violations"""
        if not self.violation_log.exists():
            return []

        cutoff_time = datetime.now() - timedelta(hours=hours)
        violations = []

        try:
            with open(self.violation_log, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        data['severity'] = PolicySeverity(data['severity'])
                        violation = PolicyViolation(**data)

                        # Parse timestamp
                        v_time = datetime.fromisoformat(violation.timestamp)
                        if v_time < cutoff_time:
                            continue

                        # Filter by severity
                        if severity and violation.severity != severity:
                            continue

                        violations.append(violation)
                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue
        except Exception:
            pass

        return violations

    def generate_compliance_report(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> ComplianceReport:
        """Generate compliance report for a period"""
        if not end_date:
            end_date = datetime.now()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        # Get violations in period
        violations = []
        if self.violation_log.exists():
            with open(self.violation_log, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        data['severity'] = PolicySeverity(data['severity'])
                        violation = PolicyViolation(**data)

                        v_time = datetime.fromisoformat(violation.timestamp)
                        if start_date <= v_time <= end_date:
                            violations.append(violation)
                    except Exception:
                        continue

        # Calculate compliance score
        # 100% if no violations, decreases based on severity
        penalty = 0
        for v in violations:
            if v.severity == PolicySeverity.CRITICAL:
                penalty += 10
            elif v.severity == PolicySeverity.HIGH:
                penalty += 5
            elif v.severity == PolicySeverity.MEDIUM:
                penalty += 2
            elif v.severity == PolicySeverity.LOW:
                penalty += 1

        compliance_score = max(0, 100 - penalty)

        return ComplianceReport(
            report_id=hashlib.sha256(
                f"{start_date}{end_date}".encode()
            ).hexdigest()[:12],
            generated_at=datetime.now().isoformat(),
            period_start=start_date.isoformat(),
            period_end=end_date.isoformat(),
            total_operations=0,  # TODO: Track from logs
            violations=violations,
            policies_checked=[p.id for p in self.policies.values() if p.enabled],
            compliance_score=compliance_score
        )

    def enforce_data_retention(self):
        """Enforce data retention policies"""
        policy = self.policies.get('data_retention')
        if not policy or not policy.enabled:
            return

        rules = policy.rules
        now = datetime.now()

        # Clean processed files
        processed_days = rules.get('processed_days', 90)
        processed_cutoff = now - timedelta(days=processed_days)
        self._cleanup_directory(Path('processed'), processed_cutoff)

        # Clean failed files
        failed_days = rules.get('failed_days', 180)
        failed_cutoff = now - timedelta(days=failed_days)
        self._cleanup_directory(Path('failed'), failed_cutoff)

        # Clean logs
        logs_days = rules.get('logs_days', 365)
        logs_cutoff = now - timedelta(days=logs_days)
        self._cleanup_directory(Path('logs'), logs_cutoff, exclude_patterns=['audit*'])

    def _cleanup_directory(
        self,
        directory: Path,
        cutoff_date: datetime,
        exclude_patterns: List[str] = None
    ):
        """Clean up old files in a directory"""
        if not directory.exists():
            return

        exclude_patterns = exclude_patterns or []

        for file_path in directory.iterdir():
            if file_path.is_file():
                # Check if excluded
                if any(file_path.match(pattern) for pattern in exclude_patterns):
                    continue

                try:
                    file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if file_time < cutoff_date:
                        file_path.unlink()
                except Exception:
                    pass


class ComplianceTracker:
    """Track compliance metrics over time"""

    def __init__(self):
        self.metrics_file = Path('state/compliance_metrics.jsonl')
        self.metrics_file.parent.mkdir(parents=True, exist_ok=True)

    def record_metric(
        self,
        metric_type: str,
        value: Any,
        tags: Dict[str, str] = None
    ):
        """Record a compliance metric"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'metric_type': metric_type,
            'value': value,
            'tags': tags or {}
        }

        with open(self.metrics_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    def get_metrics(
        self,
        metric_type: Optional[str] = None,
        hours: int = 24
    ) -> List[Dict[str, Any]]:
        """Get compliance metrics"""
        if not self.metrics_file.exists():
            return []

        cutoff_time = datetime.now() - timedelta(hours=hours)
        metrics = []

        try:
            with open(self.metrics_file, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        entry_time = datetime.fromisoformat(entry['timestamp'])

                        if entry_time < cutoff_time:
                            continue

                        if metric_type and entry.get('metric_type') != metric_type:
                            continue

                        metrics.append(entry)
                    except Exception:
                        continue
        except Exception:
            pass

        return metrics


# Global instances
_policy_engine: Optional[PolicyEngine] = None
_compliance_tracker: Optional[ComplianceTracker] = None


def get_policy_engine() -> PolicyEngine:
    """Get global policy engine instance"""
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine()
    return _policy_engine


def get_compliance_tracker() -> ComplianceTracker:
    """Get global compliance tracker instance"""
    global _compliance_tracker
    if _compliance_tracker is None:
        _compliance_tracker = ComplianceTracker()
    return _compliance_tracker
