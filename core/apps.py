import os
import logging
from django.apps import AppConfig
from django.conf import settings
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger("core_apps")
scheduler = BackgroundScheduler()


def register_pipeline_cron(pipeline: dict):
    cron_expr = pipeline.get("cron", "0 * * * *")
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        logger.warning(f"Invalid cron expression for pipeline {pipeline['id']!r}: {cron_expr!r}. Skipping.")
        return
    minute, hour, day, month, day_of_week = parts
    trigger = CronTrigger(
        minute=minute, hour=hour, day=day,
        month=month, day_of_week=day_of_week
    )
    scheduler.add_job(
        check_pipeline_task,
        trigger=trigger,
        args=[pipeline["id"]],
        id=pipeline["id"],
        replace_existing=True,
        name="check_pipeline_task"
    )
    logger.info(f"Registered background cron check for pipeline {pipeline['id']!r} with schedule: {cron_expr}")


def check_pipeline_task(pipeline_id: str):
    logger.info(f"Scheduled audit run triggered for pipeline: {pipeline_id}")
    try:
        from core.views import perform_pipeline_check
        perform_pipeline_check(pipeline_id)
    except Exception as e:
        logger.error(f"Scheduled check failed for {pipeline_id}: {e}")


class CoreConfig(AppConfig):
    name = 'core'

    def ready(self):
        # Apply the monkey-patch for the third-party schema_guard.db module
        import sys
        from core import db_impl
        sys.modules['schema_guard.db'] = db_impl
        import schema_guard
        schema_guard.db = db_impl

        # Apply monkey-patch for missing functions in schema_guard.alerter
        import schema_guard.alerter as alerter
        def mock_send_slack_alert(violations, webhook_url=None):
            logger.info(f"Slack alert triggered for violations: {violations} to {webhook_url}")
            return True
        def mock_send_whatsapp_alert(violations, phone=None):
            logger.info(f"WhatsApp alert triggered for violations: {violations} to {phone}")
            return True
        def mock_send_alert(violations):
            logger.info(f"Default alert triggered for violations: {violations}")
            return True

        def patched_send_email_alert(violations, email_to=None):
            import os
            from django.core.mail import send_mail
            from django.conf import settings
            
            if not email_to:
                email_to = os.getenv("EMAIL_TO")
            if not email_to:
                logger.error("[alerter] No recipient configured for schema drift alert email.")
                return False

            subject = "⚠️ SCHEMA DRIFT DETECTED - Contract Violation"
            violations_text = "\n".join(f"- {v}" for v in violations)
            violations_html_items = "".join(f"<li style='margin-bottom: 8px;'>❌ {v}</li>" for v in violations)

            html_message = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Schema Drift Detected</title>
            </head>
            <body style="font-family: 'Outfit', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #030712; color: #f3f4f6; margin: 0; padding: 40px 20px;">
                <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 580px; background: linear-gradient(135deg, #0b0f19 0%, #111827 100%); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(0,0,0,0.7); border-collapse: collapse;">
                    <!-- Top neon accent bar -->
                    <tr>
                        <td height="4" style="background: linear-gradient(90deg, #ef4444, #b91c1c, #fca5a5);"></td>
                    </tr>
                    <!-- Logo & Header -->
                    <tr>
                        <td style="padding: 40px 40px 20px 40px; text-align: center;">
                            <div style="display: inline-block; background: rgba(239, 68, 68, 0.08); border: 1.5px solid rgba(239, 68, 68, 0.3); border-radius: 12px; padding: 12px 20px; text-align: center; margin-bottom: 25px;">
                                <span style="font-size: 24px; vertical-align: middle;">⚠️</span>
                                <span style="font-size: 18px; font-weight: 800; color: #ffffff; letter-spacing: 1px; vertical-align: middle; margin-left: 8px; font-family: 'Outfit', sans-serif;">Drift <span style="color: #ef4444;">Detected</span></span>
                            </div>
                            <h1 style="color: #ffffff; font-size: 24px; font-weight: 800; margin: 0; font-family: 'Outfit', sans-serif; letter-spacing: -0.02em;">Data Contract Violation</h1>
                        </td>
                    </tr>
                    <!-- Body Content -->
                    <tr>
                        <td style="padding: 20px 40px 40px 40px; color: #9ca3af; line-height: 1.65; font-size: 15px;">
                            <p style="margin-top: 0; margin-bottom: 20px;">Our automated compliance gate detected one or more structural anomalies matching your database schema baseline. Please reconcile the changes immediately to protect downstream consumers:</p>
                            
                            <div style="background: rgba(24, 8, 8, 0.85); border: 1.5px solid #ef4444; border-radius: 12px; padding: 25px; margin: 25px 0; box-shadow: 0 0 20px rgba(239, 68, 68, 0.15);">
                                <ul style="margin: 0; padding-left: 0; list-style-type: none; color: #fecaca; font-family: 'Courier New', Courier, monospace; font-size: 13px; line-height: 1.7;">
                                    {violations_html_items}
                                </ul>
                            </div>
                            
                            <p style="margin-top: 20px; margin-bottom: 0;">Please check the <strong>Schema Guard Dashboard</strong> to inspect visual comparison maps, view impact analysis, and generate repair SQL scripts.</p>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 25px 40px; background-color: #020617; border-top: 1px solid rgba(255,255,255,0.04); text-align: center; font-size: 12px; color: #4b5563; line-height: 1.5;">
                            Sent by Schema Guard Automated Policy Engine.<br>
                            <span style="color: #6b7280;">Continuous Schema Gatekeeping & Drift Compliance Engine</span>
                        </td>
                    </tr>
                </table>
            </body>
            </html>
            """
            try:
                recipient_list = [e.strip() for e in email_to.split(",") if e.strip()]
                print(f"\n========================================\n[EMAIL] Drift alert to {recipient_list}:\n{violations_text}\n========================================\n")
                send_mail(
                    subject,
                    violations_text,
                    settings.DEFAULT_FROM_EMAIL,
                    recipient_list,
                    fail_silently=False,
                    html_message=html_message
                )
                return True
            except Exception as e:
                logger.error(f"Failed to send schema drift alert email: {e}")
                return False

        alerter.send_slack_alert = mock_send_slack_alert
        alerter.send_whatsapp_alert = mock_send_whatsapp_alert
        alerter.send_alert = mock_send_alert
        alerter.send_email_alert = patched_send_email_alert

        # Apply monkey-patch for missing get_tables in BaseExtractor
        from schema_guard.extractors.base import BaseExtractor
        from sqlalchemy import create_engine, inspect
        def base_get_tables(self, connection_details, schema_name):
            driver_map = {
                "PostgresExtractor": "postgresql",
                "MySQLExtractor": "mysql",
                "SQLServerExtractor": "mssql",
                "OracleExtractor": "oracle",
                "SnowflakeExtractor": "snowflake",
                "DatabricksExtractor": "databricks"
            }
            class_name = self.__class__.__name__
            default_driver = driver_map.get(class_name, "postgresql")
            connection_string = self.make_sqlalchemy_url(connection_details, default_driver)
            engine = create_engine(connection_string)
            try:
                inspector = inspect(engine)
                return inspector.get_table_names(schema=schema_name)
            finally:
                engine.dispose()
        BaseExtractor.get_tables = base_get_tables

        # Apply monkey-patch for missing get_schemas in BaseExtractor
        def base_get_schemas(self, connection_details):
            driver_map = {
                "PostgresExtractor": "postgresql",
                "MySQLExtractor": "mysql",
                "SQLServerExtractor": "mssql",
                "OracleExtractor": "oracle",
                "SnowflakeExtractor": "snowflake",
                "DatabricksExtractor": "databricks"
            }
            class_name = self.__class__.__name__
            default_driver = driver_map.get(class_name, "postgresql")
            connection_string = self.make_sqlalchemy_url(connection_details, default_driver)
            engine = create_engine(connection_string)
            try:
                inspector = inspect(engine)
                return inspector.get_schema_names()
            finally:
                engine.dispose()
        BaseExtractor.get_schemas = base_get_schemas

