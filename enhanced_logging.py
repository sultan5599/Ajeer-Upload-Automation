#!/usr/bin/env python3
"""
Enhanced Logging System for Ajeer Automation
Provides structured JSON logging, log analysis, and log viewer
"""

import json
import logging
import os
import gzip
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from logging.handlers import RotatingFileHandler
import hashlib


class StructuredLogger:
    """
    Enhanced logger with JSON structured logging and analytics
    """

    def __init__(self, log_dir: Path = Path('logs')):
        self.log_dir = log_dir
        self.log_dir.mkdir(exist_ok=True)

        # Create separate logs for different purposes
        self.logs = {
            'main': self.log_dir / 'application.log',
            'audit': self.log_dir / 'audit.log',
            'performance': self.log_dir / 'performance.log',
            'security': self.log_dir / 'security.log',
            'errors': self.log_dir / 'errors.log',
            'structured': self.log_dir / 'structured.jsonl'  # JSON Lines format
        }

        self.setup_loggers()

    def setup_loggers(self):
        """Setup all logging handlers"""
        # Main application logger
        self.app_logger = self._create_logger(
            'ajeer.app',
            self.logs['main'],
            max_bytes=5*1024*1024,  # 5MB
            backup_count=10
        )

        # Audit logger (never rotates, append-only)
        self.audit_logger = self._create_logger(
            'ajeer.audit',
            self.logs['audit'],
            max_bytes=10*1024*1024,  # 10MB
            backup_count=50
        )

        # Performance logger
        self.perf_logger = self._create_logger(
            'ajeer.performance',
            self.logs['performance'],
            max_bytes=5*1024*1024,
            backup_count=5
        )

        # Security logger
        self.security_logger = self._create_logger(
            'ajeer.security',
            self.logs['security'],
            max_bytes=10*1024*1024,
            backup_count=20
        )

        # Error logger
        self.error_logger = self._create_logger(
            'ajeer.errors',
            self.logs['errors'],
            max_bytes=5*1024*1024,
            backup_count=10,
            level=logging.ERROR
        )

    def _create_logger(
        self,
        name: str,
        log_file: Path,
        max_bytes: int = 5*1024*1024,
        backup_count: int = 10,
        level: int = logging.DEBUG
    ) -> logging.Logger:
        """Create a logger with rotating file handler"""
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.handlers.clear()

        handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger

    def log_structured(
        self,
        event_type: str,
        level: str = 'INFO',
        **kwargs
    ):
        """
        Log structured data in JSON format

        Args:
            event_type: Type of event (e.g., 'pdf_processed', 'login_attempt')
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            **kwargs: Additional key-value pairs to log
        """
        entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'level': level,
            **kwargs
        }

        # Write to JSON Lines file
        with open(self.logs['structured'], 'a') as f:
            f.write(json.dumps(entry) + '\n')

        # Also log to appropriate logger
        log_func = getattr(self.app_logger, level.lower(), self.app_logger.info)
        log_func(f"{event_type}: {json.dumps(kwargs)}")

    def log_audit(self, action: str, user: str = 'system', **details):
        """Log audit event"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'user': user,
            'details': details,
            'hash': self._compute_hash(action, user, details)
        }

        self.audit_logger.info(json.dumps(entry))
        self.log_structured('audit', level='INFO', **entry)

    def log_performance(
        self,
        operation: str,
        duration_ms: float,
        **metrics
    ):
        """Log performance metrics"""
        entry = {
            'operation': operation,
            'duration_ms': duration_ms,
            'metrics': metrics
        }

        self.perf_logger.info(json.dumps(entry))
        self.log_structured('performance', level='INFO', **entry)

    def log_security(self, event: str, severity: str = 'MEDIUM', **details):
        """Log security event"""
        entry = {
            'event': event,
            'severity': severity,
            'details': details
        }

        self.security_logger.warning(json.dumps(entry))
        self.log_structured('security', level='WARNING', **entry)

    def log_error(self, error: Exception, context: str = '', **details):
        """Log error with context"""
        entry = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'context': context,
            'details': details
        }

        self.error_logger.error(json.dumps(entry), exc_info=True)
        self.log_structured('error', level='ERROR', **entry)

    def _compute_hash(self, *args) -> str:
        """Compute hash for audit trail integrity"""
        data = json.dumps(args, sort_keys=True).encode()
        return hashlib.sha256(data).hexdigest()[:16]

    def get_recent_logs(
        self,
        log_type: str = 'main',
        hours: int = 24,
        limit: int = 1000
    ) -> List[str]:
        """Get recent log entries"""
        log_file = self.logs.get(log_type)
        if not log_file or not log_file.exists():
            return []

        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_logs = []

        try:
            with open(log_file, 'r') as f:
                for line in f:
                    recent_logs.append(line.strip())
                    if len(recent_logs) >= limit:
                        recent_logs.pop(0)  # Keep only recent ones
        except Exception:
            pass

        return recent_logs

    def get_structured_logs(
        self,
        event_type: Optional[str] = None,
        hours: int = 24,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Get structured logs with optional filtering"""
        if not self.logs['structured'].exists():
            return []

        cutoff_time = datetime.now() - timedelta(hours=hours)
        logs = []

        try:
            with open(self.logs['structured'], 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())

                        # Parse timestamp
                        log_time = datetime.fromisoformat(entry['timestamp'])
                        if log_time < cutoff_time:
                            continue

                        # Filter by event type if specified
                        if event_type and entry.get('event_type') != event_type:
                            continue

                        logs.append(entry)

                        if len(logs) >= limit:
                            logs.pop(0)
                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue
        except Exception:
            pass

        return logs

    def analyze_logs(self, hours: int = 24) -> Dict[str, Any]:
        """Analyze logs and return metrics"""
        logs = self.get_structured_logs(hours=hours)

        if not logs:
            return {
                'total_events': 0,
                'by_type': {},
                'by_level': {},
                'errors': 0,
                'warnings': 0,
                'time_range': {'start': None, 'end': None}
            }

        # Count by event type
        by_type = {}
        by_level = {}

        for log in logs:
            event_type = log.get('event_type', 'unknown')
            level = log.get('level', 'INFO')

            by_type[event_type] = by_type.get(event_type, 0) + 1
            by_level[level] = by_level.get(level, 0) + 1

        return {
            'total_events': len(logs),
            'by_type': by_type,
            'by_level': by_level,
            'errors': by_level.get('ERROR', 0) + by_level.get('CRITICAL', 0),
            'warnings': by_level.get('WARNING', 0),
            'time_range': {
                'start': logs[0]['timestamp'] if logs else None,
                'end': logs[-1]['timestamp'] if logs else None
            }
        }

    def compress_old_logs(self, days_old: int = 7):
        """Compress old log files to save space"""
        cutoff_date = datetime.now() - timedelta(days=days_old)

        for log_file in self.log_dir.glob('*.log.*'):
            try:
                if log_file.stat().st_mtime < cutoff_date.timestamp():
                    if not str(log_file).endswith('.gz'):
                        # Compress the file
                        with open(log_file, 'rb') as f_in:
                            with gzip.open(f"{log_file}.gz", 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)

                        # Remove original
                        log_file.unlink()
            except Exception:
                pass

    def cleanup_old_logs(self, days_to_keep: int = 90):
        """Remove very old compressed logs"""
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)

        for log_file in self.log_dir.glob('*.gz'):
            try:
                if log_file.stat().st_mtime < cutoff_date.timestamp():
                    log_file.unlink()
            except Exception:
                pass

    def export_logs(
        self,
        output_file: Path,
        log_type: str = 'structured',
        hours: int = 24,
        format: str = 'json'
    ):
        """Export logs to file"""
        if log_type == 'structured':
            logs = self.get_structured_logs(hours=hours, limit=100000)
        else:
            logs = self.get_recent_logs(log_type=log_type, hours=hours, limit=100000)

        if format == 'json':
            with open(output_file, 'w') as f:
                json.dump(logs, f, indent=2)
        else:  # CSV
            if isinstance(logs, list) and logs and isinstance(logs[0], dict):
                import csv
                with open(output_file, 'w', newline='') as f:
                    if logs:
                        writer = csv.DictWriter(f, fieldnames=logs[0].keys())
                        writer.writeheader()
                        writer.writerows(logs)


class LogAnalyzer:
    """Analyze logs for patterns and insights"""

    def __init__(self, logger: StructuredLogger):
        self.logger = logger

    def get_error_patterns(self, hours: int = 24) -> Dict[str, int]:
        """Identify common error patterns"""
        logs = self.logger.get_structured_logs(event_type='error', hours=hours)

        error_counts = {}
        for log in logs:
            error_type = log.get('error_type', 'Unknown')
            error_counts[error_type] = error_counts.get(error_type, 0) + 1

        return dict(sorted(error_counts.items(), key=lambda x: x[1], reverse=True))

    def get_performance_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get performance statistics"""
        logs = self.logger.get_structured_logs(event_type='performance', hours=hours)

        if not logs:
            return {}

        operations = {}
        for log in logs:
            op = log.get('operation', 'unknown')
            duration = log.get('duration_ms', 0)

            if op not in operations:
                operations[op] = {'count': 0, 'total_ms': 0, 'min_ms': float('inf'), 'max_ms': 0}

            operations[op]['count'] += 1
            operations[op]['total_ms'] += duration
            operations[op]['min_ms'] = min(operations[op]['min_ms'], duration)
            operations[op]['max_ms'] = max(operations[op]['max_ms'], duration)

        # Calculate averages
        for op in operations:
            operations[op]['avg_ms'] = operations[op]['total_ms'] / operations[op]['count']

        return operations

    def get_success_rate(self, hours: int = 24) -> float:
        """Calculate success rate for PDF processing"""
        logs = self.logger.get_structured_logs(hours=hours)

        processed = sum(1 for log in logs if log.get('event_type') == 'pdf_processed')
        failed = sum(1 for log in logs if log.get('event_type') == 'pdf_failed')

        total = processed + failed
        if total == 0:
            return 0.0

        return (processed / total) * 100

    def detect_anomalies(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Detect anomalous patterns in logs"""
        anomalies = []

        # Check for excessive errors
        error_logs = self.logger.get_structured_logs(event_type='error', hours=1)
        if len(error_logs) > 10:
            anomalies.append({
                'type': 'excessive_errors',
                'severity': 'HIGH',
                'message': f'{len(error_logs)} errors in the last hour',
                'timestamp': datetime.now().isoformat()
            })

        # Check for slow operations
        perf_stats = self.get_performance_stats(hours=1)
        for op, stats in perf_stats.items():
            if stats['avg_ms'] > 30000:  # 30 seconds
                anomalies.append({
                    'type': 'slow_operation',
                    'severity': 'MEDIUM',
                    'message': f'{op} averaging {stats["avg_ms"]/1000:.1f}s',
                    'timestamp': datetime.now().isoformat()
                })

        # Check for security events
        security_logs = self.logger.get_structured_logs(event_type='security', hours=1)
        if len(security_logs) > 5:
            anomalies.append({
                'type': 'security_alerts',
                'severity': 'CRITICAL',
                'message': f'{len(security_logs)} security events in the last hour',
                'timestamp': datetime.now().isoformat()
            })

        return anomalies


# Global logger instance
_global_logger: Optional[StructuredLogger] = None


def get_logger() -> StructuredLogger:
    """Get global logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = StructuredLogger()
    return _global_logger


def setup_logging(log_dir: Path = Path('logs')) -> StructuredLogger:
    """Setup and return enhanced logger"""
    global _global_logger
    _global_logger = StructuredLogger(log_dir)
    return _global_logger
