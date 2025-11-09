#!/usr/bin/env python3
"""
Analytics and Dashboard Module for Ajeer Automation
Provides data analysis, visualizations, and reporting
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class ProcessingStats:
    """Processing statistics"""
    timestamp: str
    total_processed: int
    successful: int
    failed: int
    duplicates: int
    success_rate: float
    average_processing_time_ms: float
    files_per_hour: float


@dataclass
class TrendData:
    """Trend analysis data"""
    period: str  # 'hourly', 'daily', 'weekly', 'monthly'
    data_points: List[Tuple[str, float]]  # (timestamp, value)
    trend_direction: str  # 'up', 'down', 'stable'
    percentage_change: float


class Analytics:
    """
    Analytics engine for processing data and generating insights
    """

    def __init__(self):
        self.stats_file = Path('state/processing_stats.jsonl')
        self.stats_file.parent.mkdir(parents=True, exist_ok=True)

    def record_processing(
        self,
        success: bool,
        processing_time_ms: float,
        file_name: str,
        duplicate: bool = False,
        error: Optional[str] = None
    ):
        """Record a processing event"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'success': success,
            'duplicate': duplicate,
            'processing_time_ms': processing_time_ms,
            'file_name': file_name,
            'error': error
        }

        with open(self.stats_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    def get_processing_events(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get processing events"""
        if not self.stats_file.exists():
            return []

        cutoff_time = datetime.now() - timedelta(hours=hours)
        events = []

        try:
            with open(self.stats_file, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        event_time = datetime.fromisoformat(event['timestamp'])

                        if event_time < cutoff_time:
                            continue

                        events.append(event)
                    except Exception:
                        continue
        except Exception:
            pass

        return events

    def get_processing_stats(self, hours: int = 24) -> ProcessingStats:
        """Get processing statistics"""
        events = self.get_processing_events(hours=hours)

        if not events:
            return ProcessingStats(
                timestamp=datetime.now().isoformat(),
                total_processed=0,
                successful=0,
                failed=0,
                duplicates=0,
                success_rate=0.0,
                average_processing_time_ms=0.0,
                files_per_hour=0.0
            )

        successful = sum(1 for e in events if e.get('success'))
        duplicates = sum(1 for e in events if e.get('duplicate'))
        failed = len(events) - successful - duplicates

        success_rate = (successful / len(events) * 100) if events else 0.0

        processing_times = [e.get('processing_time_ms', 0) for e in events if e.get('processing_time_ms')]
        avg_time = sum(processing_times) / len(processing_times) if processing_times else 0.0

        files_per_hour = len(events) / (hours if hours > 0 else 1)

        return ProcessingStats(
            timestamp=datetime.now().isoformat(),
            total_processed=len(events),
            successful=successful,
            failed=failed,
            duplicates=duplicates,
            success_rate=success_rate,
            average_processing_time_ms=avg_time,
            files_per_hour=files_per_hour
        )

    def get_hourly_stats(self, hours: int = 24) -> List[Tuple[str, int, int]]:
        """Get hourly processing stats (hour, successful, failed)"""
        events = self.get_processing_events(hours=hours)

        hourly_data = defaultdict(lambda: {'success': 0, 'failed': 0})

        for event in events:
            try:
                event_time = datetime.fromisoformat(event['timestamp'])
                hour_key = event_time.strftime('%Y-%m-%d %H:00')

                if event.get('success') and not event.get('duplicate'):
                    hourly_data[hour_key]['success'] += 1
                else:
                    hourly_data[hour_key]['failed'] += 1
            except Exception:
                continue

        # Sort by hour
        sorted_data = sorted(hourly_data.items())

        return [(hour, data['success'], data['failed']) for hour, data in sorted_data]

    def get_daily_stats(self, days: int = 30) -> List[Tuple[str, int, int]]:
        """Get daily processing stats (date, successful, failed)"""
        events = self.get_processing_events(hours=days * 24)

        daily_data = defaultdict(lambda: {'success': 0, 'failed': 0})

        for event in events:
            try:
                event_time = datetime.fromisoformat(event['timestamp'])
                day_key = event_time.strftime('%Y-%m-%d')

                if event.get('success') and not event.get('duplicate'):
                    daily_data[day_key]['success'] += 1
                else:
                    daily_data[day_key]['failed'] += 1
            except Exception:
                continue

        # Sort by date
        sorted_data = sorted(daily_data.items())

        return [(day, data['success'], data['failed']) for day, data in sorted_data]

    def get_error_distribution(self, hours: int = 24) -> Dict[str, int]:
        """Get distribution of errors"""
        events = self.get_processing_events(hours=hours)

        error_counts = defaultdict(int)

        for event in events:
            if not event.get('success'):
                error = event.get('error', 'Unknown')
                # Simplify error message
                if 'timeout' in error.lower():
                    error_type = 'Timeout'
                elif 'connection' in error.lower():
                    error_type = 'Connection Error'
                elif 'pdf' in error.lower():
                    error_type = 'PDF Processing Error'
                elif 'validation' in error.lower():
                    error_type = 'Validation Error'
                else:
                    error_type = 'Other'

                error_counts[error_type] += 1

        return dict(sorted(error_counts.items(), key=lambda x: x[1], reverse=True))

    def get_processing_time_trend(self, hours: int = 24) -> TrendData:
        """Analyze processing time trends"""
        hourly_stats = self.get_hourly_stats(hours=hours)

        if len(hourly_stats) < 2:
            return TrendData(
                period='hourly',
                data_points=[],
                trend_direction='stable',
                percentage_change=0.0
            )

        events = self.get_processing_events(hours=hours)

        # Group by hour and calculate average processing time
        hourly_times = defaultdict(list)

        for event in events:
            try:
                event_time = datetime.fromisoformat(event['timestamp'])
                hour_key = event_time.strftime('%Y-%m-%d %H:00')
                processing_time = event.get('processing_time_ms', 0)

                if processing_time > 0:
                    hourly_times[hour_key].append(processing_time)
            except Exception:
                continue

        # Calculate averages
        data_points = []
        for hour, times in sorted(hourly_times.items()):
            avg_time = sum(times) / len(times) if times else 0
            data_points.append((hour, avg_time))

        # Calculate trend
        if len(data_points) >= 2:
            first_half = sum(t[1] for t in data_points[:len(data_points)//2]) / (len(data_points)//2)
            second_half = sum(t[1] for t in data_points[len(data_points)//2:]) / (len(data_points) - len(data_points)//2)

            percentage_change = ((second_half - first_half) / first_half * 100) if first_half > 0 else 0

            if percentage_change > 10:
                trend_direction = 'up'
            elif percentage_change < -10:
                trend_direction = 'down'
            else:
                trend_direction = 'stable'
        else:
            percentage_change = 0.0
            trend_direction = 'stable'

        return TrendData(
            period='hourly',
            data_points=data_points,
            trend_direction=trend_direction,
            percentage_change=percentage_change
        )

    def get_success_rate_trend(self, days: int = 7) -> TrendData:
        """Analyze success rate trends"""
        daily_stats = self.get_daily_stats(days=days)

        if len(daily_stats) < 2:
            return TrendData(
                period='daily',
                data_points=[],
                trend_direction='stable',
                percentage_change=0.0
            )

        data_points = []
        for day, success, failed in daily_stats:
            total = success + failed
            success_rate = (success / total * 100) if total > 0 else 0
            data_points.append((day, success_rate))

        # Calculate trend
        if len(data_points) >= 2:
            first_half = sum(t[1] for t in data_points[:len(data_points)//2]) / (len(data_points)//2)
            second_half = sum(t[1] for t in data_points[len(data_points)//2:]) / (len(data_points) - len(data_points)//2)

            percentage_change = second_half - first_half  # Absolute change for percentage

            if percentage_change > 5:
                trend_direction = 'up'
            elif percentage_change < -5:
                trend_direction = 'down'
            else:
                trend_direction = 'stable'
        else:
            percentage_change = 0.0
            trend_direction = 'stable'

        return TrendData(
            period='daily',
            data_points=data_points,
            trend_direction=trend_direction,
            percentage_change=percentage_change
        )

    def generate_dashboard_data(self) -> Dict[str, Any]:
        """Generate complete dashboard data"""
        # Current stats
        stats_24h = self.get_processing_stats(hours=24)
        stats_7d = self.get_processing_stats(hours=24*7)

        # Trends
        processing_time_trend = self.get_processing_time_trend(hours=24)
        success_rate_trend = self.get_success_rate_trend(days=7)

        # Charts data
        hourly_stats = self.get_hourly_stats(hours=24)
        daily_stats = self.get_daily_stats(days=7)
        error_distribution = self.get_error_distribution(hours=24)

        return {
            'stats_24h': asdict(stats_24h),
            'stats_7d': asdict(stats_7d),
            'processing_time_trend': asdict(processing_time_trend),
            'success_rate_trend': asdict(success_rate_trend),
            'hourly_chart': {
                'labels': [h[0] for h in hourly_stats],
                'successful': [h[1] for h in hourly_stats],
                'failed': [h[2] for h in hourly_stats]
            },
            'daily_chart': {
                'labels': [d[0] for d in daily_stats],
                'successful': [d[1] for d in daily_stats],
                'failed': [d[2] for d in daily_stats]
            },
            'error_distribution': error_distribution,
            'generated_at': datetime.now().isoformat()
        }

    def export_report(
        self,
        output_file: Path,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ):
        """Export analytics report"""
        if not end_date:
            end_date = datetime.now()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        hours = int((end_date - start_date).total_seconds() / 3600)

        report = {
            'report_type': 'processing_analytics',
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'stats': asdict(self.get_processing_stats(hours=hours)),
            'hourly_breakdown': [
                {'hour': h[0], 'successful': h[1], 'failed': h[2]}
                for h in self.get_hourly_stats(hours=min(hours, 24*7))
            ],
            'error_distribution': self.get_error_distribution(hours=hours),
            'generated_at': datetime.now().isoformat()
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)


class Dashboard:
    """
    Dashboard data aggregator
    """

    def __init__(self):
        self.analytics = Analytics()

    def get_kpis(self) -> Dict[str, Any]:
        """Get Key Performance Indicators"""
        stats_24h = self.analytics.get_processing_stats(hours=24)
        stats_7d = self.analytics.get_processing_stats(hours=24*7)

        return {
            'success_rate_24h': {
                'value': stats_24h.success_rate,
                'label': 'Success Rate (24h)',
                'unit': '%',
                'trend': 'up' if stats_24h.success_rate > 90 else 'down'
            },
            'files_processed_24h': {
                'value': stats_24h.total_processed,
                'label': 'Files Processed (24h)',
                'unit': 'files',
                'trend': 'stable'
            },
            'avg_processing_time': {
                'value': stats_24h.average_processing_time_ms / 1000,
                'label': 'Avg Processing Time',
                'unit': 's',
                'trend': 'stable'
            },
            'files_per_hour': {
                'value': stats_24h.files_per_hour,
                'label': 'Throughput',
                'unit': 'files/hour',
                'trend': 'stable'
            },
            'success_rate_7d': {
                'value': stats_7d.success_rate,
                'label': 'Success Rate (7d)',
                'unit': '%',
                'trend': 'stable'
            },
            'total_files_7d': {
                'value': stats_7d.total_processed,
                'label': 'Total Files (7d)',
                'unit': 'files',
                'trend': 'stable'
            }
        }

    def get_chart_data(self, chart_type: str) -> Dict[str, Any]:
        """Get data for specific chart type"""
        if chart_type == 'hourly':
            hourly = self.analytics.get_hourly_stats(hours=24)
            return {
                'labels': [h[0].split(' ')[1] for h in hourly],  # Extract hour
                'datasets': [
                    {
                        'label': 'Successful',
                        'data': [h[1] for h in hourly],
                        'color': '#22c55e'
                    },
                    {
                        'label': 'Failed',
                        'data': [h[2] for h in hourly],
                        'color': '#f87171'
                    }
                ]
            }
        elif chart_type == 'daily':
            daily = self.analytics.get_daily_stats(days=7)
            return {
                'labels': [d[0] for d in daily],
                'datasets': [
                    {
                        'label': 'Successful',
                        'data': [d[1] for d in daily],
                        'color': '#22c55e'
                    },
                    {
                        'label': 'Failed',
                        'data': [d[2] for d in daily],
                        'color': '#f87171'
                    }
                ]
            }
        elif chart_type == 'errors':
            errors = self.analytics.get_error_distribution(hours=24)
            return {
                'labels': list(errors.keys()),
                'data': list(errors.values()),
                'colors': ['#f87171', '#fb923c', '#fbbf24', '#facc15', '#a3e635']
            }
        else:
            return {}

    def get_recent_activity(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent processing activity"""
        events = self.analytics.get_processing_events(hours=24)

        # Get the most recent events
        recent = events[-limit:] if len(events) > limit else events
        recent.reverse()

        return [
            {
                'timestamp': e['timestamp'],
                'file_name': e.get('file_name', 'Unknown'),
                'status': 'success' if e.get('success') else 'failed',
                'processing_time_ms': e.get('processing_time_ms', 0),
                'error': e.get('error')
            }
            for e in recent
        ]


# Global instance
_analytics: Optional[Analytics] = None
_dashboard: Optional[Dashboard] = None


def get_analytics() -> Analytics:
    """Get global analytics instance"""
    global _analytics
    if _analytics is None:
        _analytics = Analytics()
    return _analytics


def get_dashboard() -> Dashboard:
    """Get global dashboard instance"""
    global _dashboard
    if _dashboard is None:
        _dashboard = Dashboard()
    return _dashboard
