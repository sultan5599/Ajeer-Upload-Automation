#!/usr/bin/env python3
"""
Control and Scheduling Module for Ajeer Automation
Provides job scheduling, batch control, and automation management
"""

import json
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import uuid


class JobStatus(Enum):
    """Job execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SCHEDULED = "scheduled"


class ScheduleType(Enum):
    """Schedule types"""
    ONE_TIME = "one_time"
    RECURRING = "recurring"
    CRON = "cron"


@dataclass
class Job:
    """Represents a processing job"""
    id: str
    name: str
    status: JobStatus
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    files: List[str]
    results: Dict[str, Any]
    error: Optional[str]
    priority: int = 5  # 1-10, 10 is highest
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class Schedule:
    """Represents a scheduled automation"""
    id: str
    name: str
    schedule_type: ScheduleType
    enabled: bool
    next_run: str
    last_run: Optional[str]
    cron_expression: Optional[str]  # For CRON schedules
    interval_minutes: Optional[int]  # For RECURRING schedules
    run_time: Optional[str]  # For ONE_TIME schedules
    job_config: Dict[str, Any]
    created_at: str


class JobQueue:
    """
    Job queue manager for batch processing
    """

    def __init__(self):
        self.jobs: Dict[str, Job] = {}
        self.queue: List[str] = []  # Job IDs in priority order
        self.jobs_file = Path('state/jobs.json')
        self.jobs_file.parent.mkdir(parents=True, exist_ok=True)
        self.load_jobs()

    def create_job(
        self,
        name: str,
        files: List[str],
        priority: int = 5
    ) -> Job:
        """Create a new job"""
        job = Job(
            id=str(uuid.uuid4())[:8],
            name=name,
            status=JobStatus.PENDING,
            created_at=datetime.now().isoformat(),
            started_at=None,
            completed_at=None,
            files=files,
            results={},
            error=None,
            priority=priority,
            retry_count=0,
            max_retries=3
        )

        self.jobs[job.id] = job
        self.enqueue(job.id)
        self.save_jobs()

        return job

    def enqueue(self, job_id: str):
        """Add job to queue based on priority"""
        if job_id in self.queue:
            return

        job = self.jobs.get(job_id)
        if not job:
            return

        # Insert based on priority (higher priority first)
        inserted = False
        for i, queued_id in enumerate(self.queue):
            queued_job = self.jobs.get(queued_id)
            if queued_job and job.priority > queued_job.priority:
                self.queue.insert(i, job_id)
                inserted = True
                break

        if not inserted:
            self.queue.append(job_id)

    def dequeue(self) -> Optional[Job]:
        """Get next job from queue"""
        while self.queue:
            job_id = self.queue.pop(0)
            job = self.jobs.get(job_id)

            if job and job.status == JobStatus.PENDING:
                return job

        return None

    def update_job_status(
        self,
        job_id: str,
        status: JobStatus,
        results: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ):
        """Update job status"""
        job = self.jobs.get(job_id)
        if not job:
            return

        job.status = status

        if status == JobStatus.RUNNING:
            job.started_at = datetime.now().isoformat()
        elif status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
            job.completed_at = datetime.now().isoformat()

        if results:
            job.results = results

        if error:
            job.error = error

        self.save_jobs()

    def retry_job(self, job_id: str) -> bool:
        """Retry a failed job"""
        job = self.jobs.get(job_id)
        if not job:
            return False

        if job.retry_count >= job.max_retries:
            return False

        job.retry_count += 1
        job.status = JobStatus.PENDING
        job.error = None
        self.enqueue(job_id)
        self.save_jobs()

        return True

    def cancel_job(self, job_id: str):
        """Cancel a job"""
        job = self.jobs.get(job_id)
        if not job:
            return

        if job.status in [JobStatus.PENDING, JobStatus.SCHEDULED]:
            job.status = JobStatus.CANCELLED
            job.completed_at = datetime.now().isoformat()

            # Remove from queue
            if job_id in self.queue:
                self.queue.remove(job_id)

            self.save_jobs()

    def get_job(self, job_id: str) -> Optional[Job]:
        """Get job by ID"""
        return self.jobs.get(job_id)

    def get_all_jobs(
        self,
        status: Optional[JobStatus] = None
    ) -> List[Job]:
        """Get all jobs, optionally filtered by status"""
        jobs = list(self.jobs.values())

        if status:
            jobs = [j for j in jobs if j.status == status]

        # Sort by created_at descending
        jobs.sort(key=lambda j: j.created_at, reverse=True)

        return jobs

    def get_queue_stats(self) -> Dict[str, int]:
        """Get queue statistics"""
        return {
            'total': len(self.jobs),
            'pending': sum(1 for j in self.jobs.values() if j.status == JobStatus.PENDING),
            'running': sum(1 for j in self.jobs.values() if j.status == JobStatus.RUNNING),
            'completed': sum(1 for j in self.jobs.values() if j.status == JobStatus.COMPLETED),
            'failed': sum(1 for j in self.jobs.values() if j.status == JobStatus.FAILED),
            'cancelled': sum(1 for j in self.jobs.values() if j.status == JobStatus.CANCELLED),
            'in_queue': len(self.queue)
        }

    def cleanup_old_jobs(self, days: int = 30):
        """Clean up old completed jobs"""
        cutoff_date = datetime.now() - timedelta(days=days)

        jobs_to_remove = []
        for job_id, job in self.jobs.items():
            if job.status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
                try:
                    completed_time = datetime.fromisoformat(job.completed_at)
                    if completed_time < cutoff_date:
                        jobs_to_remove.append(job_id)
                except Exception:
                    pass

        for job_id in jobs_to_remove:
            del self.jobs[job_id]

        if jobs_to_remove:
            self.save_jobs()

    def save_jobs(self):
        """Save jobs to file"""
        data = {
            'jobs': {
                job_id: {
                    **asdict(job),
                    'status': job.status.value
                }
                for job_id, job in self.jobs.items()
            },
            'queue': self.queue
        }

        with open(self.jobs_file, 'w') as f:
            json.dump(data, f, indent=2)

    def load_jobs(self):
        """Load jobs from file"""
        if not self.jobs_file.exists():
            return

        try:
            with open(self.jobs_file, 'r') as f:
                data = json.load(f)

            for job_id, job_data in data.get('jobs', {}).items():
                job_data['status'] = JobStatus(job_data['status'])
                self.jobs[job_id] = Job(**job_data)

            self.queue = data.get('queue', [])
        except Exception:
            pass


class Scheduler:
    """
    Job scheduler for automated processing
    """

    def __init__(self):
        self.schedules: Dict[str, Schedule] = {}
        self.schedules_file = Path('config/schedules.json')
        self.schedules_file.parent.mkdir(parents=True, exist_ok=True)
        self.scheduler_thread: Optional[threading.Thread] = None
        self.running = False
        self.job_callback: Optional[Callable[[Schedule], None]] = None
        self.load_schedules()

    def create_schedule(
        self,
        name: str,
        schedule_type: ScheduleType,
        job_config: Dict[str, Any],
        cron_expression: Optional[str] = None,
        interval_minutes: Optional[int] = None,
        run_time: Optional[str] = None
    ) -> Schedule:
        """Create a new schedule"""
        schedule = Schedule(
            id=str(uuid.uuid4())[:8],
            name=name,
            schedule_type=schedule_type,
            enabled=True,
            next_run=self._calculate_next_run(
                schedule_type, cron_expression, interval_minutes, run_time
            ),
            last_run=None,
            cron_expression=cron_expression,
            interval_minutes=interval_minutes,
            run_time=run_time,
            job_config=job_config,
            created_at=datetime.now().isoformat()
        )

        self.schedules[schedule.id] = schedule
        self.save_schedules()

        return schedule

    def _calculate_next_run(
        self,
        schedule_type: ScheduleType,
        cron_expression: Optional[str],
        interval_minutes: Optional[int],
        run_time: Optional[str]
    ) -> str:
        """Calculate next run time"""
        now = datetime.now()

        if schedule_type == ScheduleType.ONE_TIME and run_time:
            try:
                next_run = datetime.fromisoformat(run_time)
                if next_run < now:
                    next_run = now + timedelta(minutes=1)
                return next_run.isoformat()
            except Exception:
                pass

        elif schedule_type == ScheduleType.RECURRING and interval_minutes:
            next_run = now + timedelta(minutes=interval_minutes)
            return next_run.isoformat()

        elif schedule_type == ScheduleType.CRON and cron_expression:
            # Simplified cron parsing (daily at specific time)
            # Format: "HH:MM"
            try:
                hour, minute = cron_expression.split(':')
                next_run = now.replace(hour=int(hour), minute=int(minute), second=0, microsecond=0)

                if next_run <= now:
                    next_run += timedelta(days=1)

                return next_run.isoformat()
            except Exception:
                pass

        # Default: 1 hour from now
        return (now + timedelta(hours=1)).isoformat()

    def update_schedule(
        self,
        schedule_id: str,
        enabled: Optional[bool] = None,
        job_config: Optional[Dict[str, Any]] = None
    ):
        """Update a schedule"""
        schedule = self.schedules.get(schedule_id)
        if not schedule:
            return

        if enabled is not None:
            schedule.enabled = enabled

        if job_config is not None:
            schedule.job_config = job_config

        self.save_schedules()

    def delete_schedule(self, schedule_id: str):
        """Delete a schedule"""
        if schedule_id in self.schedules:
            del self.schedules[schedule_id]
            self.save_schedules()

    def get_schedule(self, schedule_id: str) -> Optional[Schedule]:
        """Get schedule by ID"""
        return self.schedules.get(schedule_id)

    def get_all_schedules(self) -> List[Schedule]:
        """Get all schedules"""
        return list(self.schedules.values())

    def check_due_schedules(self) -> List[Schedule]:
        """Check for schedules that are due to run"""
        now = datetime.now()
        due_schedules = []

        for schedule in self.schedules.values():
            if not schedule.enabled:
                continue

            try:
                next_run = datetime.fromisoformat(schedule.next_run)
                if next_run <= now:
                    due_schedules.append(schedule)
            except Exception:
                continue

        return due_schedules

    def mark_schedule_run(self, schedule_id: str):
        """Mark schedule as run and calculate next run time"""
        schedule = self.schedules.get(schedule_id)
        if not schedule:
            return

        schedule.last_run = datetime.now().isoformat()

        # Calculate next run time
        if schedule.schedule_type == ScheduleType.ONE_TIME:
            # One-time schedules are disabled after running
            schedule.enabled = False
        else:
            schedule.next_run = self._calculate_next_run(
                schedule.schedule_type,
                schedule.cron_expression,
                schedule.interval_minutes,
                schedule.run_time
            )

        self.save_schedules()

    def start(self, job_callback: Callable[[Schedule], None]):
        """Start the scheduler"""
        if self.running:
            return

        self.job_callback = job_callback
        self.running = True

        def scheduler_loop():
            while self.running:
                try:
                    # Check for due schedules
                    due_schedules = self.check_due_schedules()

                    for schedule in due_schedules:
                        if self.job_callback:
                            try:
                                self.job_callback(schedule)
                                self.mark_schedule_run(schedule.id)
                            except Exception:
                                pass

                except Exception:
                    pass

                # Check every 30 seconds
                time.sleep(30)

        self.scheduler_thread = threading.Thread(target=scheduler_loop, daemon=True)
        self.scheduler_thread.start()

    def stop(self):
        """Stop the scheduler"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)

    def save_schedules(self):
        """Save schedules to file"""
        data = {
            'schedules': {
                schedule_id: {
                    **asdict(schedule),
                    'schedule_type': schedule.schedule_type.value
                }
                for schedule_id, schedule in self.schedules.items()
            }
        }

        with open(self.schedules_file, 'w') as f:
            json.dump(data, f, indent=2)

    def load_schedules(self):
        """Load schedules from file"""
        if not self.schedules_file.exists():
            return

        try:
            with open(self.schedules_file, 'r') as f:
                data = json.load(f)

            for schedule_id, schedule_data in data.get('schedules', {}).items():
                schedule_data['schedule_type'] = ScheduleType(schedule_data['schedule_type'])
                self.schedules[schedule_id] = Schedule(**schedule_data)
        except Exception:
            pass


class BatchController:
    """
    Controller for batch operations
    """

    def __init__(self):
        self.current_batch: Optional[str] = None
        self.batch_paused = False

    def start_batch(self, batch_id: str):
        """Start a batch operation"""
        self.current_batch = batch_id
        self.batch_paused = False

    def pause_batch(self):
        """Pause current batch"""
        self.batch_paused = True

    def resume_batch(self):
        """Resume current batch"""
        self.batch_paused = False

    def stop_batch(self):
        """Stop current batch"""
        self.current_batch = None
        self.batch_paused = False

    def is_paused(self) -> bool:
        """Check if batch is paused"""
        return self.batch_paused

    def is_running(self) -> bool:
        """Check if batch is running"""
        return self.current_batch is not None and not self.batch_paused


# Global instances
_job_queue: Optional[JobQueue] = None
_scheduler: Optional[Scheduler] = None
_batch_controller: Optional[BatchController] = None


def get_job_queue() -> JobQueue:
    """Get global job queue instance"""
    global _job_queue
    if _job_queue is None:
        _job_queue = JobQueue()
    return _job_queue


def get_scheduler() -> Scheduler:
    """Get global scheduler instance"""
    global _scheduler
    if _scheduler is None:
        _scheduler = Scheduler()
    return _scheduler


def get_batch_controller() -> BatchController:
    """Get global batch controller instance"""
    global _batch_controller
    if _batch_controller is None:
        _batch_controller = BatchController()
    return _batch_controller
