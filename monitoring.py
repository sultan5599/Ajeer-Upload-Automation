#!/usr/bin/env python3
"""
Monitoring and Alerting Module for Ajeer Automation
Provides health checks, performance monitoring, and alerting
"""

import json
import time
import psutil
import platform
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import threading


class HealthStatus(Enum):
    """Health check status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class HealthCheck:
    """Health check result"""
    name: str
    status: HealthStatus
    message: str
    details: Dict[str, Any]
    timestamp: str
    response_time_ms: float = 0


@dataclass
class Alert:
    """System alert"""
    id: str
    severity: AlertSeverity
    title: str
    message: str
    source: str
    timestamp: str
    details: Dict[str, Any]
    acknowledged: bool = False
    resolved: bool = False


@dataclass
class SystemMetrics:
    """System performance metrics"""
    timestamp: str
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_available_mb: float
    disk_percent: float
    disk_free_gb: float
    process_count: int
    thread_count: int


class HealthMonitor:
    """
    System health monitoring
    """

    def __init__(self):
        self.checks: Dict[str, Callable[[], HealthCheck]] = {}
        self.last_results: Dict[str, HealthCheck] = {}
        self.register_default_checks()

    def register_default_checks(self):
        """Register default health checks"""
        self.register_check('system_resources', self.check_system_resources)
        self.register_check('disk_space', self.check_disk_space)
        self.register_check('directories', self.check_directories)
        self.register_check('config_files', self.check_config_files)
        self.register_check('browser', self.check_browser_availability)

    def register_check(self, name: str, check_func: Callable[[], HealthCheck]):
        """Register a health check"""
        self.checks[name] = check_func

    def check_system_resources(self) -> HealthCheck:
        """Check system resource usage"""
        start_time = time.time()

        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()

            status = HealthStatus.HEALTHY
            message = "System resources normal"

            if cpu_percent > 90:
                status = HealthStatus.DEGRADED
                message = f"High CPU usage: {cpu_percent}%"
            elif cpu_percent > 95:
                status = HealthStatus.UNHEALTHY
                message = f"Critical CPU usage: {cpu_percent}%"

            if memory.percent > 85:
                status = HealthStatus.DEGRADED
                message = f"High memory usage: {memory.percent}%"
            elif memory.percent > 95:
                status = HealthStatus.UNHEALTHY
                message = f"Critical memory usage: {memory.percent}%"

            details = {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available_mb': memory.available / (1024 * 1024)
            }

        except Exception as e:
            status = HealthStatus.UNKNOWN
            message = f"Failed to check resources: {e}"
            details = {}

        response_time = (time.time() - start_time) * 1000

        return HealthCheck(
            name='system_resources',
            status=status,
            message=message,
            details=details,
            timestamp=datetime.now().isoformat(),
            response_time_ms=response_time
        )

    def check_disk_space(self) -> HealthCheck:
        """Check disk space"""
        start_time = time.time()

        try:
            disk = psutil.disk_usage('.')

            status = HealthStatus.HEALTHY
            message = "Disk space sufficient"

            if disk.percent > 85:
                status = HealthStatus.DEGRADED
                message = f"Low disk space: {disk.percent}% used"
            elif disk.percent > 95:
                status = HealthStatus.UNHEALTHY
                message = f"Critical disk space: {disk.percent}% used"

            details = {
                'disk_percent': disk.percent,
                'disk_free_gb': disk.free / (1024**3),
                'disk_total_gb': disk.total / (1024**3)
            }

        except Exception as e:
            status = HealthStatus.UNKNOWN
            message = f"Failed to check disk: {e}"
            details = {}

        response_time = (time.time() - start_time) * 1000

        return HealthCheck(
            name='disk_space',
            status=status,
            message=message,
            details=details,
            timestamp=datetime.now().isoformat(),
            response_time_ms=response_time
        )

    def check_directories(self) -> HealthCheck:
        """Check required directories exist"""
        start_time = time.time()

        required_dirs = ['pdfs', 'processed', 'failed', 'config', 'state', 'logs']
        missing = []
        details = {}

        for dir_name in required_dirs:
            dir_path = Path(dir_name)
            exists = dir_path.exists() and dir_path.is_dir()
            details[dir_name] = 'exists' if exists else 'missing'

            if not exists:
                missing.append(dir_name)

        if not missing:
            status = HealthStatus.HEALTHY
            message = "All required directories present"
        else:
            status = HealthStatus.UNHEALTHY
            message = f"Missing directories: {', '.join(missing)}"

        response_time = (time.time() - start_time) * 1000

        return HealthCheck(
            name='directories',
            status=status,
            message=message,
            details=details,
            timestamp=datetime.now().isoformat(),
            response_time_ms=response_time
        )

    def check_config_files(self) -> HealthCheck:
        """Check configuration files"""
        start_time = time.time()

        config_file = Path('config/settings.encrypted')

        if config_file.exists():
            status = HealthStatus.HEALTHY
            message = "Configuration file present"
            details = {
                'config_exists': True,
                'config_size_kb': config_file.stat().st_size / 1024
            }
        else:
            status = HealthStatus.DEGRADED
            message = "Configuration file missing (needs setup)"
            details = {'config_exists': False}

        response_time = (time.time() - start_time) * 1000

        return HealthCheck(
            name='config_files',
            status=status,
            message=message,
            details=details,
            timestamp=datetime.now().isoformat(),
            response_time_ms=response_time
        )

    def check_browser_availability(self) -> HealthCheck:
        """Check if Playwright browsers are available"""
        start_time = time.time()

        import os
        browsers_path = os.path.join(
            os.path.expanduser('~'),
            'AppData', 'Local', 'ms-playwright'
        )

        if os.path.exists(browsers_path):
            status = HealthStatus.HEALTHY
            message = "Playwright browsers installed"
            details = {'browsers_path': browsers_path}
        else:
            status = HealthStatus.UNHEALTHY
            message = "Playwright browsers not found"
            details = {
                'browsers_path': browsers_path,
                'install_command': 'python -m playwright install chromium'
            }

        response_time = (time.time() - start_time) * 1000

        return HealthCheck(
            name='browser',
            status=status,
            message=message,
            details=details,
            timestamp=datetime.now().isoformat(),
            response_time_ms=response_time
        )

    def run_all_checks(self) -> Dict[str, HealthCheck]:
        """Run all registered health checks"""
        results = {}

        for name, check_func in self.checks.items():
            try:
                result = check_func()
                results[name] = result
                self.last_results[name] = result
            except Exception as e:
                results[name] = HealthCheck(
                    name=name,
                    status=HealthStatus.UNKNOWN,
                    message=f"Check failed: {e}",
                    details={},
                    timestamp=datetime.now().isoformat(),
                    response_time_ms=0
                )

        return results

    def get_overall_status(self) -> HealthStatus:
        """Get overall system health status"""
        if not self.last_results:
            return HealthStatus.UNKNOWN

        statuses = [check.status for check in self.last_results.values()]

        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        elif HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        elif HealthStatus.UNKNOWN in statuses:
            return HealthStatus.UNKNOWN
        else:
            return HealthStatus.HEALTHY


class MetricsCollector:
    """
    Collect and store system metrics
    """

    def __init__(self):
        self.metrics_file = Path('state/system_metrics.jsonl')
        self.metrics_file.parent.mkdir(parents=True, exist_ok=True)
        self.collection_thread: Optional[threading.Thread] = None
        self.collecting = False

    def collect_metrics(self) -> SystemMetrics:
        """Collect current system metrics"""
        try:
            cpu = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('.')

            # Try to get process info
            try:
                process = psutil.Process()
                process_count = len(process.children(recursive=True)) + 1
                thread_count = process.num_threads()
            except Exception:
                process_count = 0
                thread_count = 0

            return SystemMetrics(
                timestamp=datetime.now().isoformat(),
                cpu_percent=cpu,
                memory_percent=memory.percent,
                memory_used_mb=memory.used / (1024 * 1024),
                memory_available_mb=memory.available / (1024 * 1024),
                disk_percent=disk.percent,
                disk_free_gb=disk.free / (1024**3),
                process_count=process_count,
                thread_count=thread_count
            )
        except Exception:
            # Return empty metrics on error
            return SystemMetrics(
                timestamp=datetime.now().isoformat(),
                cpu_percent=0,
                memory_percent=0,
                memory_used_mb=0,
                memory_available_mb=0,
                disk_percent=0,
                disk_free_gb=0,
                process_count=0,
                thread_count=0
            )

    def record_metrics(self, metrics: SystemMetrics):
        """Record metrics to file"""
        with open(self.metrics_file, 'a') as f:
            f.write(json.dumps(asdict(metrics)) + '\n')

    def start_collection(self, interval_seconds: int = 60):
        """Start background metrics collection"""
        if self.collecting:
            return

        self.collecting = True

        def collect_loop():
            while self.collecting:
                try:
                    metrics = self.collect_metrics()
                    self.record_metrics(metrics)
                except Exception:
                    pass

                time.sleep(interval_seconds)

        self.collection_thread = threading.Thread(target=collect_loop, daemon=True)
        self.collection_thread.start()

    def stop_collection(self):
        """Stop background metrics collection"""
        self.collecting = False
        if self.collection_thread:
            self.collection_thread.join(timeout=5)

    def get_metrics(self, hours: int = 24) -> List[SystemMetrics]:
        """Get recent metrics"""
        if not self.metrics_file.exists():
            return []

        cutoff_time = datetime.now() - timedelta(hours=hours)
        metrics = []

        try:
            with open(self.metrics_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        metric = SystemMetrics(**data)

                        metric_time = datetime.fromisoformat(metric.timestamp)
                        if metric_time < cutoff_time:
                            continue

                        metrics.append(metric)
                    except Exception:
                        continue
        except Exception:
            pass

        return metrics

    def get_average_metrics(self, hours: int = 1) -> Optional[SystemMetrics]:
        """Get average metrics over a period"""
        metrics = self.get_metrics(hours=hours)

        if not metrics:
            return None

        return SystemMetrics(
            timestamp=datetime.now().isoformat(),
            cpu_percent=sum(m.cpu_percent for m in metrics) / len(metrics),
            memory_percent=sum(m.memory_percent for m in metrics) / len(metrics),
            memory_used_mb=sum(m.memory_used_mb for m in metrics) / len(metrics),
            memory_available_mb=sum(m.memory_available_mb for m in metrics) / len(metrics),
            disk_percent=sum(m.disk_percent for m in metrics) / len(metrics),
            disk_free_gb=sum(m.disk_free_gb for m in metrics) / len(metrics),
            process_count=int(sum(m.process_count for m in metrics) / len(metrics)),
            thread_count=int(sum(m.thread_count for m in metrics) / len(metrics))
        )


class AlertManager:
    """
    Manage system alerts
    """

    def __init__(self):
        self.alerts_file = Path('state/alerts.jsonl')
        self.alerts_file.parent.mkdir(parents=True, exist_ok=True)
        self.active_alerts: List[Alert] = []
        self.alert_handlers: List[Callable[[Alert], None]] = []

    def create_alert(
        self,
        severity: AlertSeverity,
        title: str,
        message: str,
        source: str,
        details: Dict[str, Any] = None
    ) -> Alert:
        """Create and record an alert"""
        import uuid

        alert = Alert(
            id=str(uuid.uuid4())[:8],
            severity=severity,
            title=title,
            message=message,
            source=source,
            timestamp=datetime.now().isoformat(),
            details=details or {},
            acknowledged=False,
            resolved=False
        )

        self.active_alerts.append(alert)
        self.record_alert(alert)
        self.notify_handlers(alert)

        return alert

    def record_alert(self, alert: Alert):
        """Record alert to file"""
        data = asdict(alert)
        data['severity'] = alert.severity.value

        with open(self.alerts_file, 'a') as f:
            f.write(json.dumps(data) + '\n')

    def notify_handlers(self, alert: Alert):
        """Notify all registered alert handlers"""
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception:
                pass

    def register_handler(self, handler: Callable[[Alert], None]):
        """Register an alert handler"""
        self.alert_handlers.append(handler)

    def acknowledge_alert(self, alert_id: str):
        """Acknowledge an alert"""
        for alert in self.active_alerts:
            if alert.id == alert_id:
                alert.acknowledged = True
                break

    def resolve_alert(self, alert_id: str):
        """Resolve an alert"""
        for i, alert in enumerate(self.active_alerts):
            if alert.id == alert_id:
                alert.resolved = True
                self.active_alerts.pop(i)
                break

    def get_alerts(
        self,
        hours: int = 24,
        severity: Optional[AlertSeverity] = None,
        unresolved_only: bool = False
    ) -> List[Alert]:
        """Get recent alerts"""
        if not self.alerts_file.exists():
            return []

        cutoff_time = datetime.now() - timedelta(hours=hours)
        alerts = []

        try:
            with open(self.alerts_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        data['severity'] = AlertSeverity(data['severity'])
                        alert = Alert(**data)

                        alert_time = datetime.fromisoformat(alert.timestamp)
                        if alert_time < cutoff_time:
                            continue

                        if severity and alert.severity != severity:
                            continue

                        if unresolved_only and alert.resolved:
                            continue

                        alerts.append(alert)
                    except Exception:
                        continue
        except Exception:
            pass

        return alerts

    def get_alert_summary(self, hours: int = 24) -> Dict[str, int]:
        """Get alert summary"""
        alerts = self.get_alerts(hours=hours)

        summary = {
            'total': len(alerts),
            'critical': 0,
            'error': 0,
            'warning': 0,
            'info': 0,
            'unresolved': 0
        }

        for alert in alerts:
            if alert.severity == AlertSeverity.CRITICAL:
                summary['critical'] += 1
            elif alert.severity == AlertSeverity.ERROR:
                summary['error'] += 1
            elif alert.severity == AlertSeverity.WARNING:
                summary['warning'] += 1
            elif alert.severity == AlertSeverity.INFO:
                summary['info'] += 1

            if not alert.resolved:
                summary['unresolved'] += 1

        return summary


# Global instances
_health_monitor: Optional[HealthMonitor] = None
_metrics_collector: Optional[MetricsCollector] = None
_alert_manager: Optional[AlertManager] = None


def get_health_monitor() -> HealthMonitor:
    """Get global health monitor instance"""
    global _health_monitor
    if _health_monitor is None:
        _health_monitor = HealthMonitor()
    return _health_monitor


def get_metrics_collector() -> MetricsCollector:
    """Get global metrics collector instance"""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


def get_alert_manager() -> AlertManager:
    """Get global alert manager instance"""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager
