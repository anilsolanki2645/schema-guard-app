"""
Django Management Command: run_scheduled_checks
Executes automated pipeline schema checks based on configured cron expressions.
Supports both single-sweep execution (for external cron triggers / Render cron jobs)
and continuous loop daemon mode.
"""

import time
import logging
from datetime import datetime, timezone
from django.core.management.base import BaseCommand
from core.models import Pipeline
from core.views import perform_pipeline_check

logger = logging.getLogger("scheduled_checks")


def is_pipeline_due(pipeline, now_utc: datetime) -> bool:
    """
    Evaluates whether a pipeline's cron schedule has fired since last_checked.
    Returns True if check is due, False otherwise.
    """
    if not pipeline.last_checked:
        return True

    cron_expr = (pipeline.cron or "").strip()
    if not cron_expr:
        return True

    try:
        from apscheduler.triggers.cron import CronTrigger
        trigger = CronTrigger.from_crontab(cron_expr, timezone=timezone.utc)
        last_dt = pipeline.last_checked
        if not last_dt.tzinfo:
            last_dt = last_dt.replace(tzinfo=timezone.utc)
        next_fire = trigger.get_next_fire_time(last_dt, last_dt)
        if next_fire and next_fire <= now_utc:
            return True
        return False
    except Exception as e:
        logger.warning(f"Invalid cron expression '{cron_expr}' for pipeline '{pipeline.id}': {e}. Defaulting to due.")
        return True


def execute_pipeline_sweep(pipeline_id_filter: str = None, force: bool = False, stdout=None) -> dict:
    """
    Iterates over active pipelines and executes checks on due pipelines.
    Returns a summary dict.
    """
    now = datetime.now(timezone.utc)
    query = Pipeline.objects.all()
    if pipeline_id_filter:
        query = query.filter(id=pipeline_id_filter)

    pipelines = list(query)
    stats = {
        "total_monitored": len(pipelines),
        "due_count": 0,
        "executed_count": 0,
        "clean_count": 0,
        "drifted_count": 0,
        "error_count": 0,
        "results": []
    }

    for p in pipelines:
        due = force or is_pipeline_due(p, now)
        if not due:
            continue

        stats["due_count"] += 1
        msg_prefix = f"[{p.environment.upper()}] {p.name} ({p.id}):"

        try:
            res = perform_pipeline_check(p.id)
            stats["executed_count"] += 1
            status = res.get("status", "Unknown")

            if status == "Clean":
                stats["clean_count"] += 1
                log_msg = f"✅ {msg_prefix} CLEAN"
            else:
                stats["drifted_count"] += 1
                log_msg = f"⚠️ {msg_prefix} DRIFT DETECTED"

            stats["results"].append({
                "pipeline_id": p.id,
                "name": p.name,
                "status": status,
                "success": True
            })

            if stdout:
                stdout.write(log_msg)

        except Exception as e:
            stats["error_count"] += 1
            err_msg = f"❌ {msg_prefix} ERROR - {e}"
            stats["results"].append({
                "pipeline_id": p.id,
                "name": p.name,
                "status": "ERROR",
                "error": str(e),
                "success": False
            })
            if stdout:
                stdout.write(err_msg)

    return stats


class Command(BaseCommand):
    help = "Runs automated schema checks for pipelines whose cron schedule is due."

    def add_arguments(self, parser):
        parser.add_argument(
            "--once",
            action="store_true",
            help="Run a single evaluation sweep and exit (default behavior)."
        )
        parser.add_argument(
            "--loop",
            action="store_true",
            help="Run in continuous background daemon mode."
        )
        parser.add_argument(
            "--interval",
            type=int,
            default=60,
            help="Interval in seconds between sweeps in loop mode (default: 60)."
        )
        parser.add_argument(
            "--pipeline",
            type=str,
            default=None,
            help="Target a specific pipeline ID."
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force run all pipelines regardless of whether their cron is due."
        )

    def handle(self, *args, **options):
        is_loop = options.get("loop", False)
        interval = options.get("interval", 60)
        pipeline_filter = options.get("pipeline")
        force = options.get("force", False)

        self.stdout.write(self.style.NOTICE(f"🚀 Schema Guard Scheduled Check Runner initialized at {datetime.now(timezone.utc).isoformat()}"))

        if not is_loop:
            stats = execute_pipeline_sweep(pipeline_id_filter=pipeline_filter, force=force, stdout=self.stdout)
            self.stdout.write(self.style.SUCCESS(
                f"\nSweep Complete: {stats['executed_count']} checks executed "
                f"({stats['clean_count']} Clean, {stats['drifted_count']} Drifted, {stats['error_count']} Errors) "
                f"out of {stats['total_monitored']} monitored pipelines."
            ))
            return

        self.stdout.write(self.style.NOTICE(f"Starting daemon loop with interval {interval}s. Press Ctrl+C to stop."))
        try:
            while True:
                stats = execute_pipeline_sweep(pipeline_id_filter=pipeline_filter, force=force, stdout=self.stdout)
                self.stdout.write(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Checked {stats['executed_count']} due pipelines. Sleeping {interval}s...")
                time.sleep(interval)
        except KeyboardInterrupt:
            self.stdout.write(self.style.NOTICE("Scheduled check daemon stopped by operator."))
