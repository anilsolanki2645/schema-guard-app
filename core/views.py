import os
import json
import logging
import random
import functools
from datetime import datetime, timezone
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.conf import settings
from django.db import models, OperationalError, DatabaseError

# Import core schema_guard gate submodules
from schema_guard import db
from schema_guard.extractors import get_extractor
from schema_guard.contract import load_contract, validate_contract, lock_contract, verify_contract_integrity
from schema_guard.snapshot import capture_snapshot, load_snapshot
from schema_guard.diff_engine import compare_schemas, normalize_type
from schema_guard.alerter import send_alert, send_email_alert, send_slack_alert, send_whatsapp_alert
from passlib.context import CryptContext
from core.audit import log_action
from core.security import (
    encrypt_secret,
    decrypt_secret,
    mask_connection_string,
    sanitize_sql_identifier,
    generate_api_key,
    hash_api_key,
)

logger = logging.getLogger("core_views")

pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

# Core Paths Configuration
CONTRACTS_DIR = os.getenv("CONTRACTS_DIR")
SNAPSHOTS_DIR = os.getenv("SNAPSHOTS_DIR")

if not CONTRACTS_DIR or not SNAPSHOTS_DIR:
    base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    app_contracts = os.path.join(base_path, "contracts")
    app_snapshots = os.path.join(base_path, "snapshots")
    
    if os.path.exists(app_contracts) and os.path.exists(app_snapshots):
        CONTRACTS_DIR = CONTRACTS_DIR or app_contracts
        SNAPSHOTS_DIR = SNAPSHOTS_DIR or app_snapshots
    else:
        workspace_dir = os.path.abspath(os.path.join(base_path, "..", ".."))
        parent_contracts = os.path.join(workspace_dir, "schema-guard", "contracts")
        parent_snapshots = os.path.join(workspace_dir, "schema-guard", "snapshots")
        
        CONTRACTS_DIR = CONTRACTS_DIR or parent_contracts
        SNAPSHOTS_DIR = SNAPSHOTS_DIR or parent_snapshots

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False

def resolve_connection_string(conn_str: str, db_type: str = None) -> str:
    # Decrypt if stored encrypted at rest
    decrypted = decrypt_secret(conn_str)
    if decrypted.startswith("env:"):
        var_name = decrypted.split(":", 1)[1]
        resolved = os.getenv(var_name)
        if not resolved:
            raise RuntimeError(f"Environment variable '{var_name}' is not set.")
        decrypted = decrypt_secret(resolved)
    elif decrypted.startswith("profile:"):
        profile_name = decrypted.split(":", 1)[1]
        from core.models import ConnectionProfile
        prof = ConnectionProfile.objects.filter(name=profile_name).first()
        if not prof:
            raise RuntimeError(f"Connection profile '{profile_name}' not found.")
        decrypted = decrypt_secret(prof.conn_str)
        if not db_type and prof.db_type:
            db_type = prof.db_type

    from core.db_connector import normalize_connection_url
    return normalize_connection_url(db_type, decrypted)

def ensure_contract_and_snapshot_files(pipeline_obj):
    """
    Ensure contract YAML and snapshot JSON files exist on disk for schema-guard library.
    Uses pipeline_id to guarantee multi-tenant and table-name isolation across pipelines.
    """
    os.makedirs(CONTRACTS_DIR, exist_ok=True)
    os.makedirs(SNAPSHOTS_DIR, exist_ok=True)
    
    contract_path = os.path.join(CONTRACTS_DIR, f"{pipeline_obj.id}.yaml")
    snapshot_path = os.path.join(SNAPSHOTS_DIR, f"{pipeline_obj.id}.json")
    
    # Rehydrate contract from DB if contract_yaml is configured
    if getattr(pipeline_obj, 'contract_yaml', None):
        with open(contract_path, "w", encoding="utf-8") as f:
            f.write(pipeline_obj.contract_yaml)
    elif not os.path.exists(contract_path):
        legacy_path = os.path.join(CONTRACTS_DIR, f"{pipeline_obj.table}.yaml")
        if os.path.exists(legacy_path):
            contract_path = legacy_path
            
    # Rehydrate snapshot from DB if missing on disk
    if not os.path.exists(snapshot_path):
        from core.models import SchemaSnapshot
        latest_snap = SchemaSnapshot.objects.filter(pipeline=pipeline_obj).order_by('-version').first()
        if latest_snap and latest_snap.schema_data:
            snap_payload = {
                "captured_at": latest_snap.captured_at.isoformat(),
                "hash": latest_snap.hash or pipeline_obj.lock_signature or "synced_hash",
                "schema": latest_snap.schema_data
            }
            with open(snapshot_path, "w", encoding="utf-8") as f:
                json.dump(snap_payload, f, indent=2)
        else:
            legacy_snap = os.path.join(SNAPSHOTS_DIR, f"{pipeline_obj.table}.json")
            if os.path.exists(legacy_snap):
                snapshot_path = legacy_snap
                
    return contract_path, snapshot_path

def perform_data_quality_validation(db_type, conn_str, schema_name, table_name, schema_columns):
    from sqlalchemy import create_engine, text
    import os
    
    conn_url = resolve_connection_string(conn_str)
    
    if db_type.lower() == "sqlite" and not conn_url.startswith("sqlite:///"):
        from django.conf import settings
        db_path = conn_url.replace("sqlite://", "").strip()
        if not os.path.isabs(db_path):
            db_path = os.path.join(settings.BASE_DIR, db_path)
        conn_url = f"sqlite:///{db_path}"
        
    engine = create_engine(conn_url)
    checks = []
    status = "PASS"
    
    try:
        # Sanitize identifiers safely to prevent SQL injection
        safe_table = sanitize_sql_identifier(table_name, db_type)
        if db_type.lower() in ("mysql", "sqlite") or not schema_name:
            target_table = safe_table
        else:
            safe_schema = sanitize_sql_identifier(schema_name, db_type)
            target_table = f"{safe_schema}.{safe_table}"

        with engine.connect() as conn:
            # 1. Row Count Check
            row_count_q = text(f"SELECT COUNT(*) FROM {target_table}")
            total_rows = conn.execute(row_count_q).scalar() or 0
            
            checks.append({
                "name": "Table Ingestion Volume",
                "description": "Checks if the table is populated with active data (row count > 0)",
                "metric": f"Total rows: {total_rows:,}",
                "status": "PASS" if total_rows > 0 else "FAIL"
            })
            if total_rows == 0:
                status = "FAIL"
                
            # 2. Nullability Verification for Non-Nullable Columns
            not_null_cols = [c for c in schema_columns if not c.get("nullable", True)]
            if not_null_cols:
                null_metrics = []
                failed_cols = []
                for col in not_null_cols:
                    col_name = col["name"]
                    safe_col = sanitize_sql_identifier(col_name, db_type)
                    null_q = text(f"SELECT COUNT(*) FROM {target_table} WHERE {safe_col} IS NULL")
                    null_count = conn.execute(null_q).scalar() or 0
                    null_metrics.append(f"{col_name}: {null_count} nulls")
                    if null_count > 0:
                        failed_cols.append(col_name)
                
                metric_desc = ", ".join(null_metrics)
                checks.append({
                    "name": "Null Compliance check",
                    "description": "Verifies that columns defined as NOT NULL have 0 null values in the database",
                    "metric": metric_desc,
                    "status": "PASS" if not failed_cols else "FAIL"
                })
                if failed_cols:
                    status = "FAIL"
            else:
                checks.append({
                    "name": "Null Compliance check",
                    "description": "Verifies that columns defined as NOT NULL have 0 null values in the database",
                    "metric": "No NOT NULL columns defined to check.",
                    "status": "PASS"
                })

            # 3. Primary Key Uniqueness Check
            pk_cols = [c for c in schema_columns if c.get("primary_key", False) or c.get("pk", False)]
            if pk_cols:
                pk_metrics = []
                failed_pks = []
                for col in pk_cols:
                    col_name = col["name"]
                    safe_col = sanitize_sql_identifier(col_name, db_type)
                    dup_q = text(f"SELECT COUNT({safe_col}) - COUNT(DISTINCT {safe_col}) FROM {target_table}")
                    dup_count = conn.execute(dup_q).scalar() or 0
                    pk_metrics.append(f"{col_name}: {dup_count} duplicates")
                    if dup_count > 0:
                        failed_pks.append(col_name)
                        
                metric_desc = ", ".join(pk_metrics)
                checks.append({
                    "name": "Key Uniqueness check",
                    "description": "Verifies that primary or unique columns contain unique records (zero duplicate count)",
                    "metric": metric_desc,
                    "status": "PASS" if not failed_pks else "FAIL"
                })
                if failed_pks:
                    status = "FAIL"
            else:
                checks.append({
                    "name": "Key Uniqueness check",
                    "description": "Verifies that primary or unique columns contain unique records (zero duplicate count)",
                    "metric": "No primary keys defined to check.",
                    "status": "PASS"
                })
    except Exception as e:
        status = "FAIL"
        checks.append({
            "name": "Database Connection Integrity",
            "description": "Establishes connection to check live table records",
            "metric": f"Connection error: {str(e)}",
            "status": "FAIL"
        })
    finally:
        engine.dispose()
        
    return {
        "status": status,
        "checks": checks
    }

def send_custom_webhook_alert(violations, dq_report, webhook_url, pipeline_name, status_str) -> bool:
    import json
    import urllib.request
    from datetime import datetime, timezone

    payload = {
        "event": "schema_guard.drift_detected" if violations else "schema_guard.data_quality_failure",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pipeline": pipeline_name,
        "status": status_str,
        "schema_violations": list(violations),
        "data_quality": {
            "status": dq_report.get("status", "PASS"),
            "checks": [
                {
                    "name": c.get("name"),
                    "description": c.get("description"),
                    "metric": c.get("metric"),
                    "status": c.get("status")
                }
                for c in dq_report.get("checks", [])
            ]
        }
    }

    # SSRF Protection: Validate target URL against private/internal networks
    from urllib.parse import urlparse
    import ipaddress
    from django.conf import settings
    
    parsed = urlparse(webhook_url)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        logger.warning(f"Rejected invalid webhook URL scheme: {webhook_url}")
        return False
        
    host = (parsed.hostname or '').lower()
    blocked_hosts = {'localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254', 'metadata.google.internal'}
    if not getattr(settings, 'DEBUG', False) and not getattr(settings, 'IS_TESTING', False):
        if host in blocked_hosts or host.endswith('.internal') or host.endswith('.local'):
            logger.warning(f"SSRF protection: Rejected internal webhook host: {host}")
            return False
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                logger.warning(f"SSRF protection: Rejected private webhook IP: {host}")
                return False
        except ValueError:
            pass

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "SchemaGuard-Webhook-Dispatcher/1.0"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=8) as response:
            return response.status in [200, 201, 202, 204]
    except Exception as e:
        logger.error(f"Failed to dispatch custom webhook payload: {e}")
        return False

# -------------------------------------------------------------
# Email Helper Functions
# -------------------------------------------------------------
def generate_code() -> str:
    return "".join(random.choices("0123456789", k=6))

def send_email_helper(subject: str, message: str, to_email: str, html_message: str = None) -> bool:
    from django.core.mail import send_mail
    from django.conf import settings
    
    if isinstance(to_email, str):
        recipient_list = [e.strip() for e in to_email.split(",") if e.strip()]
    else:
        recipient_list = list(to_email)
        
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            recipient_list,
            fail_silently=False,
            html_message=html_message
        )
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {recipient_list}: {e}")
        return False

def send_verification_email(email: str, code: str) -> bool:
    subject = "Verify your Schema Guard Account"
    message = f"Your email verification code is: {code}\n\nPlease enter this code on the verification page to activate your account."
    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;800&family=JetBrains+Mono:wght@700&display=swap');
            @keyframes pulse-glow {{
                0% {{ box-shadow: 0 0 15px rgba(139, 92, 246, 0.25); border-color: rgba(139, 92, 246, 0.4); }}
                50% {{ box-shadow: 0 0 30px rgba(139, 92, 246, 0.6); border-color: rgba(139, 92, 246, 0.8); }}
                100% {{ box-shadow: 0 0 15px rgba(139, 92, 246, 0.25); border-color: rgba(139, 92, 246, 0.4); }}
            }}
            .code-glow {{
                animation: pulse-glow 2.5s infinite ease-in-out;
            }}
        </style>
    </head>
    <body style="font-family: 'Outfit', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #030712; color: #f3f4f6; margin: 0; padding: 40px 0;">
        <table align="center" border="0" cellpadding="0" cellspacing="0" width="580" style="background: linear-gradient(135deg, #0b0f19 0%, #111827 100%); border: 1px solid rgba(139, 92, 246, 0.25); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(0,0,0,0.7);">
            <!-- Top neon accent bar -->
            <tr>
                <td height="4" style="background: linear-gradient(90deg, #8b5cf6, #ec4899, #3b82f6);"></td>
            </tr>
            <!-- Logo & Header -->
            <tr>
                <td style="padding: 40px 40px 20px 40px; text-align: center;">
                    <div style="display: inline-block; background: rgba(139, 92, 246, 0.1); border: 1px solid rgba(139, 92, 246, 0.3); border-radius: 12px; padding: 12px 18px; margin-bottom: 20px;">
                        <span style="font-size: 32px; vertical-align: middle;">🛡️</span>
                        <span style="font-size: 22px; font-weight: 800; color: #ffffff; letter-spacing: 2px; vertical-align: middle; margin-left: 10px; font-family: 'Outfit', sans-serif;">SCHEMA GUARD</span>
                    </div>
                    <h1 style="color: #ffffff; font-size: 24px; font-weight: 800; margin: 0; font-family: 'Outfit', sans-serif;">Verify Your Account</h1>
                </td>
            </tr>
            <!-- Body Content -->
            <tr>
                <td style="padding: 20px 40px 40px 40px; color: #9ca3af; line-height: 1.65; font-size: 15px;">
                    <p style="margin-top: 0;">Welcome to the next generation of automated schema protection. To complete your registration and activate your credentials, please enter the following 6-digit verification code:</p>
                    
                    <div style="text-align: center; margin: 35px 0;">
                        <div class="code-glow" style="display: inline-block; background: rgba(15, 23, 42, 0.8); border: 1.5px solid #8b5cf6; border-radius: 12px; padding: 18px 40px; font-size: 38px; font-weight: 800; color: #a78bfa; font-family: 'JetBrains Mono', monospace; letter-spacing: 8px; text-shadow: 0 0 10px rgba(167, 139, 250, 0.5);">
                            {code}
                        </div>
                    </div>
                    
                    <p style="font-size: 13px; color: #6b7280; margin-top: 35px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 25px; text-align: center;">
                        If you did not request this verification code, please ignore this email.
                    </p>
                </td>
            </tr>
            <!-- Footer -->
            <tr>
                <td style="padding: 25px 40px; background-color: #020617; border-top: 1px solid rgba(255,255,255,0.04); text-align: center; font-size: 12px; color: #4b5563;">
                    Sent by Schema Guard Intelligent Agent Systems.<br>
                    <span style="color: #6b7280;">Continuous Schema Gatekeeping & Drift Compliance Engine</span>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    print(f"\n========================================\n[EMAIL] Verification code to {email}: {code}\n========================================\n")
    return send_email_helper(subject, message, email, html_message=html_message)

def send_password_reset_email(email: str, code: str) -> bool:
    subject = "Reset your Schema Guard Password"
    message = f"Your password reset code is: {code}\n\nPlease enter this code on the password reset page to update your password."
    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Your Schema Guard Password</title>
    </head>
    <body style="font-family: 'Outfit', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #030712; color: #f3f4f6; margin: 0; padding: 40px 20px;">
        <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 580px; background: linear-gradient(135deg, #0b0f19 0%, #111827 100%); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(0,0,0,0.7); border-collapse: collapse;">
            <!-- Top neon accent bar -->
            <tr>
                <td height="4" style="background: linear-gradient(90deg, #fbbf24, #d97706, #fb7185);"></td>
            </tr>
            <!-- Logo & Header -->
            <tr>
                <td style="padding: 40px 40px 20px 40px; text-align: center;">
                    <div style="display: inline-block; background: rgba(245, 158, 11, 0.08); border: 1.5px solid rgba(245, 158, 11, 0.3); border-radius: 12px; padding: 12px 20px; text-align: center; margin-bottom: 25px;">
                        <span style="font-size: 24px; vertical-align: middle;">🔑</span>
                        <span style="font-size: 18px; font-weight: 800; color: #ffffff; letter-spacing: 1px; vertical-align: middle; margin-left: 8px; font-family: 'Outfit', sans-serif;">Schema <span style="color: #fbbf24;">Guard</span></span>
                    </div>
                    <h1 style="color: #ffffff; font-size: 24px; font-weight: 800; margin: 0; font-family: 'Outfit', sans-serif; letter-spacing: -0.02em;">Password Reset Request</h1>
                </td>
            </tr>
            <!-- Body Content -->
            <tr>
                <td style="padding: 20px 40px 40px 40px; color: #9ca3af; line-height: 1.65; font-size: 15px;">
                    <p style="margin-top: 0; margin-bottom: 20px;">We received a request to reset your password. Use the secure authorization code below to configure your new password credentials:</p>
                    
                    <div style="text-align: center; margin: 35px 0;">
                        <div style="display: inline-block; background: rgba(15, 23, 42, 0.85); border: 1.5px solid #f59e0b; border-radius: 12px; padding: 18px 40px; font-size: 38px; font-weight: 800; color: #fbbf24; font-family: 'Courier New', Courier, monospace; letter-spacing: 8px; box-shadow: 0 0 20px rgba(245, 158, 11, 0.15); text-shadow: 0 0 10px rgba(245, 158, 11, 0.4);">
                            {code}
                        </div>
                    </div>
                    
                    <p style="font-size: 13px; color: #6b7280; margin-top: 35px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 25px; text-align: center; margin-bottom: 0;">
                        If you did not make this request, please change your password or contact support immediately.
                    </p>
                </td>
            </tr>
            <!-- Footer -->
            <tr>
                <td style="padding: 25px 40px; background-color: #020617; border-top: 1px solid rgba(255,255,255,0.04); text-align: center; font-size: 12px; color: #4b5563; line-height: 1.5;">
                    Sent by Schema Guard Intelligent Agent Systems.<br>
                    <span style="color: #6b7280;">Continuous Schema Gatekeeping & Drift Compliance Engine</span>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    print(f"\n========================================\n[EMAIL] Password reset code to {email}: {code}\n========================================\n")
    return send_email_helper(subject, message, email, html_message=html_message)

# -------------------------------------------------------------
# Unified Compliance Gate Check Engine
# -------------------------------------------------------------
def perform_pipeline_check(pipeline_id: str) -> dict:
    p = db.get_pipeline(pipeline_id)
    if not p:
        raise ValueError("Pipeline not found.")

    logs = []
    timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    logs.append("[INFO] Establishing connection to target database...")

    try:
        from core.models import Pipeline, SchemaSnapshot
        p_model = Pipeline.objects.filter(id=pipeline_id).first()
        contract_path, snapshot_path = ensure_contract_and_snapshot_files(p_model) if p_model else (None, None)

        if not contract_path or not os.path.exists(contract_path) or not snapshot_path or not os.path.exists(snapshot_path):
            logs.append("[INFO] Running baseline check on target database...")
            resolved_conn = resolve_connection_string(p["connStr"])
            extractor = get_extractor(p["dbType"])
            live_schema = extractor.get_schema(resolved_conn, p["schema"], p["table"])
            
            # Auto-initialize baseline if not already captured
            os.makedirs(CONTRACTS_DIR, exist_ok=True)
            os.makedirs(SNAPSHOTS_DIR, exist_ok=True)
            contract_path = os.path.join(CONTRACTS_DIR, f"{p['table']}.yaml")
            snapshot_path = os.path.join(SNAPSHOTS_DIR, f"{p['table']}.json")
            
            import yaml
            contract_data = {
                "source": {
                    "name": f"{pipeline_id}_contract",
                    "type": p["dbType"],
                    "connection": p["connStr"],
                    "schema": p["schema"],
                    "table": p["table"]
                },
                "columns": [
                    {"name": col["name"], "type": col["type"], "nullable": col["nullable"]}
                    for col in live_schema["columns"]
                ]
            }
            with open(contract_path, "w", encoding="utf-8") as f:
                yaml.dump(contract_data, f, default_flow_style=False, sort_keys=False)
            capture_snapshot(live_schema, snapshot_path)
            lock_contract(contract_path)

        logs.append("[INFO] Verifying contract signature lock integrity...")
        try:
            verify_contract_integrity(contract_path)
            logs.append("[INFO] Signature verification: PASSED.")
        except ValueError as ex:
            logs.append(f"[ERROR] Contract signature lock verification FAILED: {ex}")
            raise ex

        cfg = load_contract(contract_path)
        snapshot = load_snapshot(snapshot_path)

        logs.append("[INFO] Fetching schema catalog lists from database...")
        resolved_conn = resolve_connection_string(p["connStr"])
        extractor = get_extractor(p["dbType"])
        live_schema = extractor.get_schema(resolved_conn, p["schema"], p["table"])
        logs.append(f"[INFO] Successfully extracted schema details: {len(live_schema['columns'])} columns.")

        # Run live data quality metrics validation
        logs.append("[INFO] Running data level quality verification checks...")
        try:
            dq_report = perform_data_quality_validation(
                p["dbType"], p["connStr"], p["schema"], p["table"], live_schema["columns"]
            )
            logs.append(f"[INFO] Successfully completed data level checks. Status: {dq_report['status']}")
            if dq_report["status"] == "FAIL":
                logs.append("[WARNING] DATA QUALITY COMPLIANCE FAILURES DETECTED:")
                for check in dq_report["checks"]:
                    if check["status"] == "FAIL":
                        logs.append(f"[ERROR] Data Quality - {check['name']}: {check['metric']}")
        except Exception as e:
            logger.error(f"Data quality checks failed: {e}")
            dq_report = {
                "status": "FAIL",
                "checks": [{
                    "name": "Data Quality Engine Exception",
                    "description": "Runs data level quality checks",
                    "metric": f"Exception raised: {str(e)}",
                    "status": "FAIL"
                }]
            }
            logs.append(f"[ERROR] Data quality profiling engine failed: {e}")

        logs.append("[INFO] Running schema diff gate comparison checks...")
        violations, notices = compare_schemas(live_schema, snapshot["schema"], cfg.get("columns", []))

        schema_map = {"left": [], "right": [], "dataQuality": dq_report}
        snap_cols = {c["name"]: c for c in snapshot["schema"]["columns"]}
        live_cols = {c["name"]: c for c in live_schema["columns"]}

        for col_name, col in snap_cols.items():
            status_tag = "clean"
            if col_name not in live_cols:
                status_tag = "removed"
            elif (normalize_type(col["type"]) != normalize_type(live_cols[col_name]["type"]) or
                  col["nullable"] != live_cols[col_name]["nullable"]):
                status_tag = "changed"
            schema_map["left"].append({
                "name": col_name, "type": col["type"],
                "pk": col.get("primary_key", False),
                "nullable": col["nullable"], "status": status_tag
            })

        for col_name, col in live_cols.items():
            status_tag = "clean"
            if col_name not in snap_cols:
                status_tag = "added"
            elif (normalize_type(col["type"]) != normalize_type(snap_cols[col_name]["type"]) or
                  col["nullable"] != snap_cols[col_name]["nullable"]):
                status_tag = "changed"
            schema_map["right"].append({
                "name": col_name, "type": col["type"],
                "pk": col.get("primary_key", False),
                "nullable": col["nullable"], "status": status_tag
            })

        for n in notices:
            logs.append(f"[INFO] {n}")

        status_str = "Clean"
        if violations or dq_report["status"] == "FAIL":
            status_str = "Drifted"
            if violations:
                logs.append("[WARNING] COMPLIANCE VIOLATION DETECTED:")
                for v in violations:
                    logs.append(f"[ERROR] {v}")
                logs.append(f"[ERROR] Verification FAILED: {len(violations)} structural drift violations.")
            else:
                logs.append("[WARNING] COMPLIANCE VIOLATION DETECTED: Live data quality validation failures.")

            alert_sent = False
            desc_warnings = list(violations)
            if dq_report["status"] == "FAIL":
                for check in dq_report["checks"]:
                    if check["status"] == "FAIL":
                        desc_warnings.append(f"Data Quality - {check['name']}: {check['metric']}")

            if p["alerts"].get("email"):
                if send_email_alert(desc_warnings, email_to=p["alerts"]["email"]):
                    alert_sent = True
                    logs.append(f"[INFO] Email alert dispatched to {p['alerts']['email']}.")
            if p["alerts"].get("slack"):
                if send_slack_alert(desc_warnings, webhook_url=p["alerts"]["slack"]):
                    alert_sent = True
                    logs.append("[INFO] Slack alert dispatched.")
            if p["alerts"].get("wp"):
                if send_whatsapp_alert(desc_warnings, phone=p["alerts"]["wp"]):
                    alert_sent = True
                    logs.append(f"[INFO] WhatsApp alert dispatched to {p['alerts']['wp']}.")
            
            # Custom Webhook Event Dispatcher
            if p["alerts"].get("webhook"):
                if send_custom_webhook_alert(violations, dq_report, p["alerts"]["webhook"], p["name"], status_str):
                    alert_sent = True
                    logs.append(f"[INFO] Custom Webhook payload successfully dispatched to {p['alerts']['webhook']}.")
                else:
                    logs.append("[ERROR] Custom Webhook dispatch failed.")

            if not alert_sent:
                if send_alert(desc_warnings):
                    logs.append("[INFO] Default alert dispatched.")
        else:
            logs.append("[SUCCESS] Verification PASSED: Active schemas are in perfect alignment and data quality checks passed.")

        alert_event = ", ".join([k for k, v in p["alerts"].items() if v]) if (violations or dq_report["status"] == "FAIL") else "None"
        compliance = list(p.get("complianceHistory") or [])
        compliance.insert(0, {
            "time": timestamp_str,
            "profile": "production",
            "status": "PASS" if not violations and dq_report["status"] == "PASS" else "FAIL",
            "violations": len(violations) + sum(1 for c in dq_report["checks"] if c["status"] == "FAIL"),
            "alertEvent": alert_event
        })
        # Cap compliance history to prevent unbounded JSON growth
        MAX_COMPLIANCE_HISTORY = 100
        if len(compliance) > MAX_COMPLIANCE_HISTORY:
            compliance = compliance[:MAX_COMPLIANCE_HISTORY]

        updates = {
            "status": status_str,
            "lastChecked": timestamp_str,
            "schemaMap": schema_map,
            "logs": logs,
            "complianceHistory": compliance,
        }
        db.update_pipeline(pipeline_id, updates)

        # Record historical snapshot in database for timeline diffing
        try:
            from core.models import Pipeline, SchemaSnapshot
            p_obj_snap = Pipeline.objects.filter(id=pipeline_id).first()
            if p_obj_snap:
                last_ver = SchemaSnapshot.objects.filter(pipeline=p_obj_snap).aggregate(models.Max('version'))['version__max'] or 0
                SchemaSnapshot.objects.create(
                    pipeline=p_obj_snap,
                    version=last_ver + 1,
                    schema_data=live_schema,
                    hash=p.get("lockSignature", ""),
                    status=status_str,
                    violations_count=len(violations),
                    captured_by='system_check'
                )
        except Exception as snap_save_err:
            logger.warning(f"Could not record SchemaSnapshot history: {snap_save_err}")

        return db.get_pipeline(pipeline_id)

    except Exception as e:
        logger.error(f"Pipeline check failed: {e}")
        db.update_pipeline(pipeline_id, {
            "status": "Failed",
            "lastChecked": timestamp_str,
            "logs": logs + [f"[ERROR] Check failed: {e}"],
        })
        raise e

# -------------------------------------------------------------
# Django View Decorators & Helpers
# -------------------------------------------------------------
def require_login(view_func):
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user_info = request.session.get('user')
        if not user_info:
            return redirect('login_page')
        
        # Check direct database verification status
        from core.models import User
        user = User.objects.filter(username=user_info['username']).first()
        if not user:
            request.session.flush()
            return redirect('login_page')
        
        if not user.is_verified:
            return redirect('verify_email_page')
            
        return view_func(request, *args, **kwargs)
    return wrapper

def require_admin(view_func):
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user = request.session.get('user')
        if not user or user.get('role') not in ['admin', 'subadmin']:
            return HttpResponse("Unauthorized", status=403)
        return view_func(request, *args, **kwargs)
    return wrapper

# -------------------------------------------------------------
# Frontend HTML Template Views
# -------------------------------------------------------------
def login_page(request):
    if request.session.get('user'):
        try:
            user_info = request.session.get('user')
            from core.models import User
            user = User.objects.filter(username=user_info['username']).first()
            if user and not user.is_verified:
                return redirect('verify_email_page')
            return redirect('dashboard')
        except (OperationalError, DatabaseError) as e:
            logger.warning(f"Database check in login_page failed: {e}")
            request.session.flush()
    
    # Check if there's a messages context
    success_message = request.GET.get('success_message', '')
    error_message = request.GET.get('error_message', '')
    return render(request, 'core/login.html', {
        'success_message': success_message,
        'error_message': error_message
    })

@require_login
def dashboard_page(request):
    user_info = request.session.get('user', {})
    from core.models import User
    user = User.objects.filter(username=user_info.get('username')).first()
    org = user.organization if user else None
    return render(request, 'core/dashboard.html', {
        'org': org,
        'plan': org.plan if org else 'free',
        'max_pipelines': org.max_pipelines if org else 5
    })

@require_login
def builder_page(request):
    # Require see / edit permissions
    user_info = request.session.get('user')
    if not user_info.get('permissions', {}).get('see', True) and user_info.get('role') not in ['admin', 'subadmin']:
        return HttpResponse("Unauthorized to view yaml builder.", status=403)
    return render(request, 'core/builder.html')

@require_login
@require_admin
def admin_page(request):
    return render(request, 'core/admin.html')

@require_login
def troubleshooting_page(request):
    return render(request, 'core/troubleshooting.html')

def docs_page(request):
    """Comprehensive technical documentation & product architecture guide."""
    return render(request, 'core/docs.html')

def terms_page(request):
    """Public Terms of Service compliance agreement."""
    return render(request, 'core/terms.html')

def privacy_page(request):
    """Public GDPR/CCPA Privacy Policy and data security declaration."""
    return render(request, 'core/privacy.html')

# -------------------------------------------------------------
# Email Verification Views
# -------------------------------------------------------------
def verify_email_page(request):
    user_info = request.session.get('user')
    if not user_info:
        return redirect('login_page')
        
    from core.models import User
    user = User.objects.filter(username=user_info['username']).first()
    if not user:
        request.session.flush()
        return redirect('login_page')
        
    if user.is_verified:
        return redirect('dashboard')
        
    return render(request, 'core/verify_email.html', {'email': user.email})

def verify_email_action(request):
    if request.method != "POST":
        return redirect('verify_email_page')
        
    user_info = request.session.get('user')
    if not user_info:
        return redirect('login_page')
        
    code = request.POST.get('code', '').strip()
    from core.models import User
    user = User.objects.filter(username=user_info['username']).first()
    
    if not user:
        request.session.flush()
        return redirect('login_page')
        
    if user.verification_code == code:
        user.is_verified = True
        user.verification_code = None
        user.save()
        
        # Update session verification state
        user_info['is_verified'] = True
        request.session['user'] = user_info
        return redirect('dashboard')
    else:
        return render(request, 'core/verify_email.html', {
            'error_message': 'Invalid verification code. Please check your email and try again.',
            'email': user.email
        })

def resend_verification_code_api(request):
    user_info = request.session.get('user')
    if not user_info:
        return JsonResponse({"detail": "Unauthorized"}, status=401)
        
    from core.models import User
    user = User.objects.filter(username=user_info['username']).first()
    if not user:
        return JsonResponse({"detail": "User not found"}, status=404)
        
    code = generate_code()
    user.verification_code = code
    user.save()
    
    success = send_verification_email(user.email, code)
    if success:
        return JsonResponse({"status": "success", "message": "Verification code resent successfully."})
    else:
        return JsonResponse({"status": "warning", "message": "SMTP connection timed out. If you are the administrator, copy the code directly from your Render Service Logs."})

# -------------------------------------------------------------
# Password Reset Views
# -------------------------------------------------------------
def forgot_password_view(request):
    if request.method == "POST":
        email = request.POST.get('email', '').strip()
        from core.models import User
        user = User.objects.filter(email=email).first()
        if not user:
            return render(request, 'core/forgot_password.html', {
                'error_message': 'No account is registered with this email address.'
            })
            
        code = generate_code()
        user.reset_code = code
        user.save()
        
        success = send_password_reset_email(email, code)
        redirect_url = f'/reset-password?email={email}'
        if not success:
            redirect_url += '&email_failed=true'
        return redirect(redirect_url)
        
    return render(request, 'core/forgot_password.html')

def reset_password_view(request):
    email = request.GET.get('email', '')
    if request.method == "POST":
        email = request.POST.get('email', '').strip()
        code = request.POST.get('code', '').strip()
        password = request.POST.get('password', '').strip()
        confirm_password = request.POST.get('confirm_password', '').strip()
        
        if not code or not password or not confirm_password:
            return render(request, 'core/reset_password.html', {
                'email': email,
                'error_message': 'All fields are required.'
            })
            
        if password != confirm_password:
            return render(request, 'core/reset_password.html', {
                'email': email,
                'error_message': 'Passwords do not match.'
            })
            
        from core.models import User
        user = User.objects.filter(email=email).first()
        if not user or user.reset_code != code:
            return render(request, 'core/reset_password.html', {
                'email': email,
                'error_message': 'Invalid password reset code or email address.'
            })
            
        user.password_hash = hash_password(password)
        user.reset_code = None
        user.save()
        
        return redirect('/?success_message=Your password has been reset successfully. Please log in.')
        
    email_failed = request.GET.get('email_failed') == 'true'
    return render(request, 'core/reset_password.html', {'email': email, 'email_failed': email_failed})

# -------------------------------------------------------------
# Auth Actions APIs
# -------------------------------------------------------------
def login_or_register_view(request):
    if request.method != "POST":
        return redirect('login_page')
    
    action = request.POST.get('action')
    username = request.POST.get('username', '').strip()
    password = request.POST.get('password', '').strip()
    email = request.POST.get('email', '').strip()
    org_name = request.POST.get('organization_name', '').strip()

    if not username or not password:
        return render(request, 'core/login.html', {
            'error_message': 'Username and password are required fields.',
            'is_signup_mode': action == 'register',
            'saved_username': username,
            'saved_email': email,
            'saved_org_name': org_name
        })

    try:
        if action == 'register':
            if not email:
                return render(request, 'core/login.html', {
                    'error_message': 'Email address is required for signup.',
                    'is_signup_mode': True,
                    'saved_username': username,
                    'saved_email': email,
                    'saved_org_name': org_name
                })
                
            # If no organization name is provided, default to a personal workspace
            if not org_name:
                org_name = f"{username}'s Personal Workspace"

            if db.get_user(username):
                return render(request, 'core/login.html', {
                    'error_message': f"Username '{username}' already exists.",
                    'is_signup_mode': True,
                    'saved_username': username,
                    'saved_email': email,
                    'saved_org_name': org_name
                })
                
            # Check email uniqueness
            from core.models import User, Organization
            if User.objects.filter(email=email).exists():
                return render(request, 'core/login.html', {
                    'error_message': f"Email '{email}' is already registered with another account.",
                    'is_signup_mode': True,
                    'saved_username': username,
                    'saved_email': email,
                    'saved_org_name': org_name
                })

            if Organization.objects.filter(name=org_name).exists():
                return render(request, 'core/login.html', {
                    'error_message': f"Organization '{org_name}' already exists. Please choose a different name.",
                    'is_signup_mode': True,
                    'saved_username': username,
                    'saved_email': email,
                    'saved_org_name': org_name
                })
                
            # Register organization and make user its subadmin
            org = Organization.objects.create(name=org_name)
            
            role = "subadmin"
            permissions = {
                "see": True,
                "create": True,
                "edit": True,
                "delete": True
            }
            
            verification_code = generate_code()
            pwd_hash = hash_password(password)
            new_user = db.create_user(
                username=username,
                email=email,
                password_hash=pwd_hash,
                role=role,
                permissions=permissions,
                organization_id=org.id,
                is_verified=False,
                verification_code=verification_code
            )
            
            send_verification_email(email, verification_code)
            
            # Store user details in session cookie (marked unverified initially)
            request.session['user'] = {
                "username": new_user["username"],
                "email": new_user["email"],
                "role": new_user["role"],
                "permissions": new_user["permissions"],
                "organization_id": org.id,
                "is_verified": False
            }
            log_action(request, 'user.register', 'user', username, {'email': email, 'organization': org_name})
            return redirect('verify_email_page')

        else:
            # Login flow supporting Username OR Email login
            from core.models import User
            user_obj = User.objects.filter(models.Q(username=username) | models.Q(email=username)).first()
            
            if not user_obj or not verify_password(password, user_obj.password_hash):
                return render(request, 'core/login.html', {
                    'error_message': 'Invalid username/email or password credentials.',
                    'is_signup_mode': False,
                    'saved_username': username
                })
            
            clean_user = build_user_session_dict(user_obj)
            request.session['user'] = clean_user
            
            if not user_obj.is_verified:
                return redirect('verify_email_page')
            
            log_action(request, 'user.login', 'user', user_obj.username)
            return redirect('dashboard')
    except (OperationalError, DatabaseError) as db_err:
        logger.error(f"Database error during authentication: {db_err}")
        return render(request, 'core/login.html', {
            'error_message': 'Database connection error: Unable to reach the database server. Please check your network connection or verify database host settings in .env.',
            'is_signup_mode': action == 'register',
            'saved_username': username,
            'saved_email': email,
            'saved_org_name': org_name
        })
    except Exception as e:
        logger.error(f"Unexpected error during authentication: {e}")
        return render(request, 'core/login.html', {
            'error_message': f'Authentication error: {str(e)}',
            'is_signup_mode': action == 'register',
            'saved_username': username,
            'saved_email': email,
            'saved_org_name': org_name
        })

def logout_view(request):
    user_info = request.session.get('user')
    if user_info:
        log_action(request, 'user.logout', 'user', user_info.get('username', ''))
    request.session.flush()
    return redirect('login_page')

# -------------------------------------------------------------
# Pipelines CRUD REST APIs
# -------------------------------------------------------------
@require_login
def get_pipelines_api(request):
    user_info = request.session.get('user')
    if not user_info.get('permissions', {}).get('see', True) and user_info.get('role') not in ['admin', 'subadmin']:
        return JsonResponse({"detail": "Permission denied to see pipelines."}, status=403)
        
    if user_info.get('role') == 'admin':
        # Super Admin sees everything
        return JsonResponse(db.get_all_pipelines(), safe=False)
    else:
        # Return only pipelines belonging to user's organization
        from core.models import Pipeline
        qs = Pipeline.objects.filter(organization_id=user_info.get('organization_id')).order_by('-created_at')
        from core.db_impl import serialize_pipeline
        pipelines = [serialize_pipeline(p) for p in qs]
        return JsonResponse(pipelines, safe=False)

def check_feature_permission(org, feature_name, extra=None):
    """
    Validates if an organization's plan is allowed to use a given feature.
    Returns (True, None) if allowed, or (False, error_message) if denied.
    """
    if not org:
        plan = 'free'
    else:
        plan = (getattr(org, 'plan', 'free') or 'free').lower()

    if plan == 'enterprise':
        return True, None

    if feature_name == 'db_engine':
        engine = str(extra or '').strip().lower()
        pro_engines = ['snowflake', 'sqlserver', 'sql server', 'mssql', 'databricks', 'oracle', 'bigquery', 'redshift']
        if plan == 'free' and any(e in engine for e in pro_engines):
            return False, f"The '{extra}' database connector requires a Team Pro or Enterprise subscription. Your workspace is currently on Developer (Free)."

    elif feature_name == 'cron_frequency':
        cron = str(extra or '').strip()
        if plan == 'free' and cron:
            parts = cron.split()
            if len(parts) == 5:
                minute, hour = parts[0], parts[1]
                if minute == '*' or '/' in minute or hour == '*' or '/' in hour or ',' in hour:
                    return False, "Sub-daily check frequencies (down to 1 minute) require a Team Pro or Enterprise plan. Developer (Free) is limited to Daily audits."

    elif feature_name == 'api_keys':
        if plan == 'free':
            return False, "CI/CD Gate API Keys & programmatic tokens require Team Pro or Enterprise. Please upgrade your workspace."

    elif feature_name == 'ai_diagnostics':
        if plan == 'free':
            return False, "AI Root-Cause Diagnostics & SQL repair generator is a Team Pro & Enterprise feature. Please upgrade your workspace."

    elif feature_name == 'airflow_export':
        if plan == 'free':
            return False, "Native Airflow Operator & dbt Schema Exporter download requires Team Pro or Enterprise."

    elif feature_name == 'alerts':
        alert_channels = extra if isinstance(extra, dict) else {}
        if plan == 'free':
            if alert_channels.get('slack') or alert_channels.get('whatsapp') or alert_channels.get('webhook') or alert_channels.get('wp'):
                return False, "Slack, WhatsApp, and Webhook alert channels require Team Pro or Enterprise. Developer (Free) supports Email alerts."

    return True, None


@require_login
def create_pipeline_api(request):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    user_info = request.session.get('user')
    if not user_info.get('permissions', {}).get('create', True) and user_info.get('role') not in ['admin', 'subadmin']:
        return JsonResponse({"detail": "Permission denied to create pipelines."}, status=403)

    data = json.loads(request.body)
    raw_name = data.get("name", "").strip()
    if not raw_name:
        return JsonResponse({"detail": "Pipeline name is required."}, status=400)

    # Check organization plan pipeline quotas & feature gating
    if user_info.get('role') != 'admin' and user_info.get('organization_id'):
        from core.models import Organization, Pipeline
        org = Organization.objects.filter(id=user_info.get('organization_id')).first()
        if org:
            current_pipes = Pipeline.objects.filter(organization=org).count()
            if current_pipes >= org.max_pipelines:
                return JsonResponse({
                    "detail": f"Pipeline limit reached ({current_pipes}/{org.max_pipelines}) for your '{org.plan.upper()}' tier. Upgrade your plan to create more pipelines."
                }, status=402)

            allowed, err = check_feature_permission(org, 'db_engine', data.get("dbType"))
            if not allowed:
                return JsonResponse({"detail": err}, status=403)

            allowed, err = check_feature_permission(org, 'cron_frequency', data.get("cron"))
            if not allowed:
                if org.plan == 'free':
                    data['cron'] = '0 0 * * *'
                    data['cronText'] = 'Every Day at Midnight (Daily)'
                else:
                    return JsonResponse({"detail": err}, status=403)

            allowed, err = check_feature_permission(org, 'alerts', data.get("alerts"))
            if not allowed:
                return JsonResponse({"detail": err}, status=403)

    import re, secrets
    base_id = re.sub(r'[^a-zA-Z0-9_]', '_', raw_name.lower().replace(" ", "_")).strip('_') or "pipeline"
    pipe_id = base_id
    if db.pipeline_exists(pipe_id):
        pipe_id = f"{base_id}_{secrets.token_hex(3)}"
    
    try:
        resolved_conn = resolve_connection_string(data.get("connStr"))
        extractor = get_extractor(data.get("dbType"))
        live_schema = extractor.get_schema(resolved_conn, data.get("schema"), data.get("table"))
    except Exception as e:
        return JsonResponse({"detail": f"Could not connect or pull schema info: {e}"}, status=400)
    
    contract_path = os.path.join(CONTRACTS_DIR, f"{data.get('table')}.yaml")
    snapshot_path = os.path.join(SNAPSHOTS_DIR, f"{data.get('table')}.json")
    
    contract_data = {
        "source": {
            "name": f"{pipe_id}_contract",
            "type": data.get("dbType"),
            "connection": data.get("connStr"),
            "schema": data.get("schema"),
            "table": data.get("table")
        },
        "columns": [
            {"name": col["name"], "type": col["type"], "nullable": col["nullable"]}
            for col in live_schema["columns"]
        ]
    }
    
    import yaml
    os.makedirs(os.path.dirname(contract_path), exist_ok=True)
    contract_yaml_str = yaml.dump(contract_data, default_flow_style=False, sort_keys=False)
    with open(contract_path, "w", encoding="utf-8") as f:
        f.write(contract_yaml_str)
        
    capture_snapshot(live_schema, snapshot_path)
    
    lock_path = lock_contract(contract_path)
    with open(lock_path) as f:
        lock_info = json.load(f)
    lock_signature = lock_info.get("hash", "sha256_mock_signature")
    
    schema_map = {"left": [], "right": []}
    for col in live_schema["columns"]:
        node = {
            "name": col["name"], "type": col["type"],
            "pk": col.get("primary_key", False),
            "nullable": col["nullable"], "status": "clean"
        }
        schema_map["left"].append(node)
        schema_map["right"].append(node)
        
    # Get organization scoping
    org_id = None
    if user_info.get('role') != 'admin':
        org_id = user_info.get('organization_id')
    else:
        # Super Admin can optionally link to an organization
        org_id = data.get("organization_id")
        
    p = {
        "id": pipe_id,
        "name": data.get("name"),
        "dbType": data.get("dbType"),
        "connStr": data.get("connStr"),
        "schema": data.get("schema"),
        "table": data.get("table"),
        "cron": data.get("cron", "0 0 * * *"),
        "cronText": data.get("cronText", "Daily preset"),
        "alerts": data.get("alerts", {}),
        "status": "Clean",
        "lastChecked": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "lockSignature": lock_signature,
        "schemaMap": schema_map,
        "contractYaml": contract_yaml_str,
        "logs": ["[INFO] Registered pipeline database connection baseline successfully."],
        "complianceHistory": [{
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "profile": "production",
            "status": "PASS",
            "violations": 0,
            "alertEvent": "None"
        }],
        "organization_id": org_id
    }
    
    new_pipe = db.create_pipeline(p)
    
    # Persist initial SchemaSnapshot record in DB
    from core.models import SchemaSnapshot
    try:
        SchemaSnapshot.objects.create(
            pipeline_id=pipe_id,
            version=1,
            schema_data=live_schema,
            hash=lock_signature,
            status="Clean",
            violations_count=0,
            captured_by=user_info.get('username', 'system')
        )
    except Exception as snap_err:
        logger.warning(f"Could not persist initial SchemaSnapshot: {snap_err}")
    
    log_action(request, 'pipeline.create', 'pipeline', pipe_id, {
        'db_type': data.get('dbType'), 'table': data.get('table')
    })
    
    from core.apps import register_pipeline_cron
    try:
        register_pipeline_cron(new_pipe)
    except Exception as e:
        logger.error(f"Failed to register cron for {new_pipe['id']}: {e}")
        
    return JsonResponse(new_pipe)

@require_login
def edit_pipeline_api(request, id):
    if request.method != "PUT":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    user_info = request.session.get('user')
    if not user_info.get('permissions', {}).get('edit', True) and user_info.get('role') not in ['admin', 'subadmin']:
        return JsonResponse({"detail": "Permission denied to edit pipelines."}, status=403)
    
    p = db.get_pipeline(id)
    if not p:
        return JsonResponse({"detail": "Pipeline not found"}, status=404)
        
    # Enforce organization boundary
    if user_info.get('role') != 'admin' and p.get('organization_id') != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)
        
    data = json.loads(request.body)
    
    # Feature gating check on pipeline update
    if user_info.get('role') != 'admin' and user_info.get('organization_id'):
        from core.models import Organization
        org = Organization.objects.filter(id=user_info.get('organization_id')).first()
        if org:
            if "cron" in data:
                allowed, err = check_feature_permission(org, 'cron_frequency', data.get("cron"))
                if not allowed:
                    if org.plan == 'free':
                        data['cron'] = '0 0 * * *'
                        data['cronText'] = 'Every Day at Midnight (Daily)'
                    else:
                        return JsonResponse({"detail": err}, status=403)
            if "alerts" in data:
                allowed, err = check_feature_permission(org, 'alerts', data.get("alerts"))
                if not allowed:
                    return JsonResponse({"detail": err}, status=403)
    updates = {
        "connStr": data.get("connStr"),
        "cron": data.get("cron"),
        "cronText": data.get("cronText"),
        "alerts": data.get("alerts", {})
    }
    
    db.update_pipeline(id, updates)
    updated = db.get_pipeline(id)
    
    from core.apps import register_pipeline_cron
    try:
        register_pipeline_cron(updated)
    except Exception as e:
        logger.error(f"Failed to update cron schedule: {e}")
        
    return JsonResponse(updated)

@require_login
def delete_pipeline_api(request, id):
    if request.method != "DELETE":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    user_info = request.session.get('user')
    if not user_info.get('permissions', {}).get('delete', True) and user_info.get('role') not in ['admin', 'subadmin']:
        return JsonResponse({"detail": "Permission denied to delete pipelines."}, status=403)
        
    p = db.get_pipeline(id)
    if not p:
        return JsonResponse({"detail": "Pipeline not found"}, status=404)
        
    # Enforce organization boundary
    if user_info.get('role') != 'admin' and p.get('organization_id') != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)
        
    from core.apps import scheduler
    try:
        if scheduler.get_job(id):
            scheduler.remove_job(id)
    except Exception:
        pass
        
    try:
        tbl = p["table"]
        for fname in (f"{tbl}.yaml", f"{tbl}.yaml.lock", f"{tbl}.json"):
            d = CONTRACTS_DIR if fname.endswith((".yaml", ".lock")) else SNAPSHOTS_DIR
            path = os.path.join(d, fname)
            if os.path.exists(path):
                os.remove(path)
    except Exception:
        pass
        
    db.delete_pipeline(id)
    log_action(request, 'pipeline.delete', 'pipeline', id)
    return JsonResponse({"status": "success"})

@require_login
def list_tables_api(request):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
    
    data = json.loads(request.body)
    try:
        db_type = data.get("dbType")
        resolved_conn = resolve_connection_string(data.get("connStr"), db_type)
        from core.db_connector import get_db_tables
        tables = get_db_tables(db_type, resolved_conn, data.get("schema"))
        return JsonResponse({"tables": tables})
    except Exception as e:
        return JsonResponse({"detail": str(e)}, status=400)


@require_login
def list_schemas_api(request):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
    
    data = json.loads(request.body)
    try:
        db_type = data.get("dbType")
        resolved_conn = resolve_connection_string(data.get("connStr"), db_type)
        from core.db_connector import get_db_schemas
        schemas = get_db_schemas(db_type, resolved_conn)
        return JsonResponse({"schemas": schemas})
    except Exception as e:
        return JsonResponse({"detail": str(e)}, status=400)

@require_login
def test_connection_api(request):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    data = json.loads(request.body)
    try:
        db_type = data.get("dbType")
        resolved_conn = resolve_connection_string(data.get("connStr"), db_type)
        from core.db_connector import test_db_connection, get_db_columns
        ok, msg = test_db_connection(db_type, resolved_conn)
        if not ok:
            return JsonResponse({"status": "failed", "message": f"Connection test failed: {msg}"})
        
        schema = data.get("schema")
        table = data.get("table")
        if schema and table:
            schema_info = get_db_columns(db_type, resolved_conn, schema, table)
            return JsonResponse({"status": "success", "columns": schema_info["columns"]})
        return JsonResponse({"status": "success", "message": "Connection verified successfully."})
    except Exception as e:
        return JsonResponse({"status": "failed", "message": str(e)})

def validate_pipeline_gate_api(request, id):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    from core.models import Pipeline, GateValidationLog, ApiKey
    from django.utils import timezone as dj_tz
    p_obj = Pipeline.objects.filter(id=id).first()
    if not p_obj:
        return JsonResponse({"detail": "Pipeline not found"}, status=404)
        
    # Authentication check:
    # 1. API Key (X-Schema-Guard-Token or Authorization: Bearer <key>)
    # 2. Session authentication
    # 3. Fallback to contract lock_signature for legacy integration
    user_info = request.session.get('user')
    auth_header = request.headers.get("X-Schema-Guard-Token") or request.GET.get("token") or request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        auth_header = auth_header[7:].strip()
    
    authenticated = False
    actor = "system/api"
    
    if auth_header:
        token_hash = hash_api_key(auth_header)
        api_key = ApiKey.objects.filter(key_hash=token_hash, is_active=True).first()
        if api_key:
            if not p_obj.organization_id or api_key.organization_id == p_obj.organization_id:
                authenticated = True
                actor = f"api_key:{api_key.name}"
                api_key.last_used_at = dj_tz.now()
                api_key.save(update_fields=['last_used_at'])
        elif auth_header == p_obj.lock_signature:
            authenticated = True
            actor = "ci-cd-pipeline"
            
    if not authenticated and user_info:
        if user_info.get('role') == 'admin' or p_obj.organization_id == user_info.get('organization_id'):
            authenticated = True
            actor = user_info.get('username')
        
    if not authenticated:
        return JsonResponse({"detail": "Unauthorized: Invalid or missing API key (X-Schema-Guard-Token header)."}, status=403)
        
    try:
        data = json.loads(request.body) if request.body else {}
    except Exception:
        data = {}

    commit_sha = data.get("commit_sha", "").strip()
    branch = data.get("branch", "").strip()
    proposed_schema = data.get("schema")
    
    # Ensure contract and snapshot files exist (rehydrates from DB if needed)
    contract_path, snapshot_path = ensure_contract_and_snapshot_files(p_obj)
    
    if not os.path.exists(contract_path):
        return JsonResponse({"detail": "Data contract specifications are not configured for this pipeline."}, status=400)
        
    try:
        cfg = load_contract(contract_path)
    except Exception as e:
        return JsonResponse({"detail": f"Failed to load contract specifications: {e}"}, status=400)
        
    contract_cols = cfg.get("columns", [])
    
    # If proposed schema is not provided (e.g. from Airflow operator), extract current live table columns!
    if not proposed_schema or "columns" not in proposed_schema:
        try:
            resolved_conn = resolve_connection_string(p_obj.conn_str)
            extractor = get_extractor(p_obj.db_type)
            live_info = extractor.get_schema(resolved_conn, p_obj.schema, p_obj.table)
            proposed_cols = live_info.get("columns", [])
        except Exception as e:
            return JsonResponse({"detail": f"Could not extract live schema for gate verification: {e}"}, status=400)
    else:
        proposed_cols = proposed_schema["columns"]
    
    # Perform gate validation
    violations = []
    warnings = []
    
    contract_map = {col["name"]: col for col in contract_cols}
    proposed_names = set(col["name"] for col in proposed_cols)
    
    # Verify missing columns and mismatching rules
    for col_name, c_col in contract_map.items():
        if col_name not in proposed_names:
            violations.append(f"Column '{col_name}' is required by contract but is missing in the proposed schema.")
            continue
            
        p_col = next(col for col in proposed_cols if col["name"] == col_name)
        
        # Check nullability
        c_null = c_col.get("nullable", True)
        p_null = p_col.get("nullable", True)
        if c_null and not p_null:
            violations.append(f"Column '{col_name}' is nullable in contract but is marked as NOT NULL in the proposed schema.")
        elif not c_null and p_null:
            warnings.append(f"Column '{col_name}' is NOT NULL in contract but is marked as nullable in the proposed schema.")
            
        # Check types
        c_type = normalize_type(c_col.get("type", ""))
        p_type = normalize_type(p_col.get("type", ""))
        if c_type != p_type:
            allowed = False
            for drift in c_col.get("allowed_drift", []):
                if normalize_type(drift.get("from")) == c_type and normalize_type(drift.get("to")) == p_type:
                    allowed = True
                    break
            if not allowed:
                violations.append(f"Column '{col_name}' type mismatch: contract expects '{c_col.get('type')}', proposed has '{p_col.get('type')}'")
                
    # Warn for added columns
    proposed_map = {col["name"]: col for col in proposed_cols}
    for col_name, p_col in proposed_map.items():
        if col_name not in contract_map:
            p_null = p_col.get("nullable", True)
            if not p_null:
                warnings.append(f"New column '{col_name}' is NOT NULL. Ensure it has a default value to prevent breaking downstream ingestion.")
            else:
                warnings.append(f"New column '{col_name}' added (not defined in contract).")
                
    status_str = "FAIL" if violations else "PASS"
    
    # Save validation log entry
    log_entry = GateValidationLog.objects.create(
        pipeline=p_obj,
        commit_sha=commit_sha,
        branch=branch,
        status=status_str,
        violations_count=len(violations),
        details={
            "violations": violations,
            "warnings": warnings,
            "total_columns": len(proposed_cols)
        }
    )
    
    # Write to system audit trail
    from core.audit import log_system_action
    log_system_action(
        action='pipeline.drift_detected' if violations else 'pipeline.check',
        target_type='pipeline_gate',
        target_id=id,
        details={
            'actor': actor,
            'commit': commit_sha,
            'branch': branch,
            'status': status_str,
            'violations': len(violations)
        }
    )
    
    return JsonResponse({
        "compatible": len(violations) == 0,
        "status": status_str,
        "violations": violations,
        "warnings": warnings,
        "checked_at": log_entry.checked_at.strftime("%Y-%m-%d %H:%M:%S")
    })

@require_login
def get_gate_logs_api(request, id):
    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    user_info = request.session.get('user')
    from core.models import Pipeline, GateValidationLog
    p_obj = Pipeline.objects.filter(id=id).first()
    if not p_obj:
        return JsonResponse({"detail": "Pipeline not found"}, status=404)
        
    # Enforce organization boundary
    if user_info.get('role') != 'admin' and p_obj.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)
        
    logs_qs = GateValidationLog.objects.filter(pipeline=p_obj).order_by('-checked_at')[:50]
    logs_data = [{
        "id": log.id,
        "commit_sha": log.commit_sha,
        "branch": log.branch,
        "status": log.status,
        "violations_count": log.violations_count,
        "details": log.details,
        "checked_at": log.checked_at.strftime("%Y-%m-%d %H:%M:%S")
    } for log in logs_qs]
    
    return JsonResponse(logs_data, safe=False)

@require_login
def run_pipeline_check_api(request, id):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    user_info = request.session.get('user')
    p = db.get_pipeline(id)
    if not p:
        return JsonResponse({"detail": "Pipeline not found"}, status=404)
        
    # Enforce organization boundary
    if user_info.get('role') != 'admin' and p.get('organization_id') != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)
        
    try:
        updated = perform_pipeline_check(id)
        return JsonResponse(updated)
    except ValueError as e:
        return JsonResponse({"detail": str(e)}, status=404)
    except Exception as e:
        return JsonResponse({"detail": str(e)}, status=400)

@require_login
def run_ai_diagnostics_api(request, id):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    user_info = request.session.get('user')
    p = db.get_pipeline(id)
    if not p:
        return JsonResponse({"detail": "Pipeline not found"}, status=404)
        
    # Enforce organization boundary
    if user_info.get('role') != 'admin' and p.get('organization_id') != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)
        
    data = json.loads(request.body)
    
    # Feature gating check for AI Diagnostics
    if user_info.get('role') != 'admin':
        from core.models import Organization
        org_id = p.get('organization_id') or user_info.get('organization_id')
        org = Organization.objects.filter(id=org_id).first()
        if org:
            allowed, err = check_feature_permission(org, 'ai_diagnostics')
            if not allowed:
                return JsonResponse({"detail": err}, status=403)
    q_type = data.get("query_type")
    custom_query = data.get("custom_query", "")
    
    err_lines = [line for line in p.get("logs", []) if "[ERROR]" in line]
    drift_summary = err_lines[0] if err_lines else "Schema mismatch detected on active pipeline."
    
    # 1. Parse errors from logs
    violations = []
    if p.get("logs"):
        for line in p["logs"]:
            if "[ERROR]" in line and "Verification FAILED" not in line:
                parts = line.split("[ERROR]", 1)
                violations.append(parts[1].strip())
                
    snapshot = None
    if p.get("snapshotId"):
        try:
            snapshot = db.get_snapshot(p["snapshotId"])
        except Exception:
            pass

    # 2. Analyze violations
    import re
    parsed_violations = []
    for v in violations:
        col_name = None
        v_type = None  # "missing", "type_mismatch", "nullability_mismatch", "added"
        details = {}
        
        match = re.search(r"['`]([a-zA-Z0-9_]+)['`]", v)
        if match:
            col_name = match.group(1)
            
        if "missing" in v.lower() or "dropped" in v.lower():
            v_type = "missing"
        elif "nullable" in v.lower() or "nullability" in v.lower():
            v_type = "nullability_mismatch"
            change_match = re.search(r"nullable\s+changed\s+from\s+([a-zA-Z0-9_\s]+)\s+to\s+([a-zA-Z0-9_\s]+)", v, re.IGNORECASE)
            if change_match:
                details["expected"] = change_match.group(1).strip()
                details["got"] = change_match.group(2).strip()
            else:
                exp_match = re.search(r"expected\s+([a-zA-Z0-9_\s]+),\s+got\s+([a-zA-Z0-9_\s]+)", v, re.IGNORECASE)
                if exp_match:
                    details["expected"] = exp_match.group(1).strip()
                    details["got"] = exp_match.group(2).strip()
        elif "type" in v.lower():
            v_type = "type_mismatch"
            change_match = re.search(r"type\s+changed\s+from\s+([a-zA-Z0-9_\(\)\s]+)\s+to\s+([a-zA-Z0-9_\(\)\s]+)", v, re.IGNORECASE)
            if change_match:
                details["expected"] = change_match.group(1).strip()
                details["got"] = change_match.group(2).strip()
            else:
                exp_match = re.search(r"expected\s+([a-zA-Z0-9_\(\)\s]+),\s+got\s+([a-zA-Z0-9_\(\)\s]+)", v, re.IGNORECASE)
                if exp_match:
                    details["expected"] = exp_match.group(1).strip()
                    details["got"] = exp_match.group(2).strip()
        elif "added" in v.lower():
            v_type = "added"
            
        parsed_violations.append({
            "raw": v,
            "column": col_name,
            "type": v_type,
            "details": details
        })

    # 3. Generate dynamic SQL reconciliation script
    ddl_statements = []
    db_type = p.get("dbType", "postgres").lower()
    schema = p.get("schema", "public")
    table = p.get("table", "my_table")
    
    for pv in parsed_violations:
        col_name = pv["column"]
        v_type = pv["type"]
        details = pv["details"]
        if not col_name:
            continue
            
        snap_col = None
        if snapshot and snapshot.get("schema") and snapshot["schema"].get("columns"):
            snap_col = next((c for c in snapshot["schema"]["columns"] if c["name"] == col_name), None)
            
        expected_type = "VARCHAR(255)"
        expected_nullable = True
        if snap_col:
            expected_type = snap_col.get("type", "VARCHAR(255)")
            expected_nullable = snap_col.get("nullable", True)
            
        nullable_sql = "NULL" if expected_nullable else "NOT NULL"
        
        if v_type == "missing":
            if db_type == "postgres" or db_type == "snowflake":
                ddl_statements.append(f"ALTER TABLE {schema}.{table} ADD COLUMN {col_name} {expected_type} {nullable_sql};")
            elif db_type == "mysql":
                ddl_statements.append(f"ALTER TABLE `{table}` ADD COLUMN `{col_name}` {expected_type} {nullable_sql};")
            else:
                ddl_statements.append(f"ALTER TABLE {table} ADD COLUMN {col_name} {expected_type} {nullable_sql};")
        elif v_type == "added":
            if db_type == "postgres" or db_type == "snowflake":
                ddl_statements.append(f"ALTER TABLE {schema}.{table} DROP COLUMN {col_name};")
            elif db_type == "mysql":
                ddl_statements.append(f"ALTER TABLE `{table}` DROP COLUMN `{col_name}`;")
            else:
                ddl_statements.append(f"ALTER TABLE {table} DROP COLUMN {col_name};")
        elif v_type == "type_mismatch":
            target_type = details.get("expected", expected_type)
            if db_type == "postgres":
                ddl_statements.append(f"ALTER TABLE {schema}.{table} ALTER COLUMN {col_name} TYPE {target_type} USING {col_name}::{target_type};")
            elif db_type == "snowflake":
                ddl_statements.append(f"ALTER TABLE {schema}.{table} ALTER COLUMN {col_name} SET DATA TYPE {target_type};")
            elif db_type == "mysql":
                ddl_statements.append(f"ALTER TABLE `{table}` MODIFY `{col_name}` {target_type};")
            else:
                ddl_statements.append(f"-- SQLite does not support direct type modification. Recreate table with: {col_name} {target_type}")
        elif v_type == "nullability_mismatch":
            target_nullable_str = details.get("expected", "")
            is_nullable = True
            if "not nullable" in target_nullable_str.lower() or "false" in target_nullable_str.lower():
                is_nullable = False
                
            if db_type == "postgres" or db_type == "snowflake":
                action = "DROP NOT NULL" if is_nullable else "SET NOT NULL"
                ddl_statements.append(f"ALTER TABLE {schema}.{table} ALTER COLUMN {col_name} {action};")
            elif db_type == "mysql":
                null_sql = "NULL" if is_nullable else "NOT NULL"
                ddl_statements.append(f"ALTER TABLE `{table}` MODIFY `{col_name}` {expected_type} {null_sql};")
            else:
                action = "DROP NOT NULL" if is_nullable else "SET NOT NULL"
                ddl_statements.append(f"-- SQLite nullability constraint change: {col_name} {action}")

    # 4. Generate downstream impact analysis
    impact_items = []
    for pv in parsed_violations:
        col_name = pv["column"] or "field"
        v_type = pv["type"]
        if v_type == "missing":
            impact_items.append(f"- **BI Layer (Tableau/Looker)**: Dashboard panels depending on `{col_name}` will fail to render.")
            impact_items.append(f"- **ETL Load Jobs**: Downstream Spark/dbt models expecting `{col_name}` will throw compilation or runtime schema errors.")
            impact_items.append(f"- **API Consumers**: Any client-side services expecting `{col_name}` in the response JSON payload will encounter null-pointer exceptions.")
        elif v_type == "type_mismatch":
            expected = pv["details"].get("expected", "expected_type")
            got = pv["details"].get("got", "actual_type")
            impact_items.append(f"- **Data Warehousing**: Casting exceptions when aggregating or partitioning on `{col_name}` (expected `{expected}`, live is `{got}`).")
            impact_items.append(f"- **API Deserialization**: ORM models or data transfer objects (DTOs) in backend APIs may crash when casting `{col_name}`.")
        elif v_type == "nullability_mismatch":
            expected = pv["details"].get("expected", "nullable")
            got = pv["details"].get("got", "not nullable")
            impact_items.append(f"- **Write Path Integrity**: If the database was set to `NOT NULL` but upstream expected `nullable`, insert transactions omitting `{col_name}` will raise `IntegrityError` exceptions.")

    # 5. Rebuild Contract YAML
    yaml_lines = [f"# Updated contract specification for {schema}.{table}", "columns:"]
    if snapshot and snapshot.get("schema") and snapshot["schema"].get("columns"):
        for c in snapshot["schema"]["columns"]:
            c_name = c["name"]
            c_type = c["type"]
            c_null = c["nullable"]
            
            pv_change = next((pv for pv in parsed_violations if pv["column"] == c_name), None)
            if pv_change:
                if pv_change["type"] == "type_mismatch":
                    c_type = pv_change["details"].get("got", c_type)
                elif pv_change["type"] == "nullability_mismatch":
                    got_null_str = pv_change["details"].get("got", "True")
                    c_null = "false" not in got_null_str.lower() and "not nullable" not in got_null_str.lower()
                    
            yaml_lines.append(f"  - name: {c_name}")
            yaml_lines.append(f"    type: {c_type}")
            yaml_lines.append(f"    nullable: {str(c_null).lower()}")
            
        for pv in parsed_violations:
            if pv["type"] == "added" and pv["column"]:
                yaml_lines.append(f"  - name: {pv['column']}")
                yaml_lines.append(f"    type: VARCHAR(255) # Auto-detected new column")
                yaml_lines.append(f"    nullable: true")

    # 6. Response Router
    response_msg = ""
    if q_type == "explain":
        if impact_items:
            response_msg = (
                f"**Downstream Application Impact Analysis**:\n\n"
                f"The detected drift violations will impact the following consumption layers:\n\n" + 
                "\n".join(impact_items)
            )
        else:
            response_msg = (
                f"**Downstream Application Impact Analysis**:\n\n"
                f"No structural violations were found. Your downstream BI tools, ETL jobs, and APIs are safe from schema-driven failures."
            )
            
    elif q_type == "sql":
        if ddl_statements:
            sql_script = "\n".join(ddl_statements)
            response_msg = (
                f"**SQL Schema Reconciliation Repair Script**:\n\n"
                f"To restore compliance and match the registered snapshot baseline state, execute the following dialect-specific SQL query on your `{db_type}` database:\n\n"
                f"```sql\n"
                f"{sql_script}\n"
                f"```\n\n"
                f"Once executed, run verification to clear the alert."
            )
        else:
            response_msg = (
                f"**SQL Schema Reconciliation Repair Script**:\n\n"
                f"The schema is fully compliant. No repair DDL statements are needed."
            )
            
    elif q_type == "yaml":
        yaml_content = "\n".join(yaml_lines)
        response_msg = (
            f"**Updated Data Contract YAML Representation**:\n\n"
            f"If the database mutations are authorized upgrades, copy and re-sign this new YAML configuration in the **YAML Contract Builder**:\n\n"
            f"```yaml\n"
            f"{yaml_content}\n"
            f"```\n\n"
            f"Click **Lock Contract Signature** to lock-in the layout."
        )
        
    else:  # Custom query
        cq_lower = custom_query.lower()
        if not violations:
            response_msg = "Hello! I am your Schema Guard Copilot. No active drifts are detected on this table. Everything is in alignment! How can I help you today?"
        elif any(k in cq_lower for k in ["tableau", "looker", "powerbi", "bi", "dashboard", "charts"]):
            impact_details = "\n".join([item for item in impact_items if "BI" in item or "Dashboard" in item]) or "BI dashboards will fail due to missing/renamed dimensions or attributes."
            response_msg = (
                f"**BI Dashboard Impact Report**:\n\n"
                f"Looking at table `{schema}.{table}`, here is how the drift impacts your dashboards:\n\n"
                f"{impact_details}\n\n"
                f"*Recommendation*: Do not refresh workbook extracts until you either execute the SQL repair script or update the workbook structure."
            )
        elif any(k in cq_lower for k in ["dbt", "model", "schema.yml", "yaml"]):
            # Generate dbt schema.yml
            dbt_cols = []
            if snapshot and snapshot.get("schema") and snapshot["schema"].get("columns"):
                for c in snapshot["schema"]["columns"]:
                    dbt_cols.append(f"      - name: {c['name']}\n        description: \"Data contract verified column ({c['type']})\"")
            dbt_cols_str = "\n".join(dbt_cols)
            response_msg = (
                f"**dbt schema.yml Specification**:\n\n"
                f"Here is the generated dbt model configuration matching this table:\n\n"
                f"```yaml\n"
                f"version: 2\n"
                f"models:\n"
                f"  - name: {table}\n"
                f"    description: \"Compliance-guarded schema model for {schema}.{table}\"\n"
                f"    columns:\n"
                f"{dbt_cols_str}\n"
                f"```"
            )
        elif any(k in cq_lower for k in ["sql", "fix", "ddl", "repair", "migration", "query"]):
            sql_script = "\n".join(ddl_statements) or "-- No DDL changes required"
            response_msg = (
                f"**SQL DDL Migration Script**:\n\n"
                f"Here is the SQL snippet to repair the live table `{schema}.{table}`:\n\n"
                f"```sql\n"
                f"{sql_script}\n"
                f"```"
            )
        else:
            first_err = violations[0] if violations else "mismatch"
            response_msg = (
                f"Regarding your query about table `{schema}.{table}`: *\"{custom_query}\"*.\n\n"
                f"The active compliance drift is: `{first_err}`.\n\n"
                f"You can resolve this in two ways:\n"
                f"1. **Align Database**: Apply the generated SQL repair script to align the live table structure with the contract.\n"
                f"2. **Update Contract**: Re-snap the contract in the **Contract Builder** if the database changes are intentional.\n\n"
                f"Let me know if you would like me to generate a specific code config or explain a particular detail."
            )
        
    return JsonResponse({
        "drift_summary": drift_summary,
        "response": response_msg
    })

# -------------------------------------------------------------
# Administrative User & Organization Management APIs
# -------------------------------------------------------------
@require_login
@require_admin
def get_users_api(request):
    user_info = request.session.get('user')
    if user_info.get('role') == 'admin':
        return JsonResponse(db.get_all_users(), safe=False)
    else:
        from core.models import User
        qs = User.objects.filter(organization_id=user_info.get('organization_id')).order_by('-created_at')
        from core.db_impl import serialize_user
        users = [serialize_user(u) for u in qs]
        return JsonResponse(users, safe=False)

@require_login
@require_admin
def create_user_api(request):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    user_info = request.session.get('user')
    data = json.loads(request.body)
    
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "operator")
    permissions = data.get("permissions", {"see": True, "create": False, "edit": False, "delete": False})
    
    if not username or not email or not password:
        return JsonResponse({"detail": "Username, email, and password are required fields."}, status=400)
        
    if db.get_user(username):
        return JsonResponse({"detail": f"Username '{username}' already exists."}, status=400)
        
    from core.models import User
    if User.objects.filter(email=email).exists():
        return JsonResponse({"detail": f"Email '{email}' is already registered."}, status=400)
        
    org_id = None
    if user_info.get('role') == 'subadmin':
        org_id = user_info.get('organization_id')
        if role not in ['operator', 'viewer']:
            role = 'operator'
    else:
        org_id = data.get("organization_id")
        
    verification_code = generate_code()
    new_user = db.create_user(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role=role,
        permissions=permissions,
        organization_id=org_id,
        is_verified=False,
        verification_code=verification_code
    )
    
    send_verification_email(email, verification_code)
    return JsonResponse(new_user)

@require_login
@require_admin
def update_user_api(request, username):
    if request.method != "PUT":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    if username == 'admin':
        return JsonResponse({"detail": "Cannot modify main administrator account role."}, status=400)
        
    user_info = request.session.get('user')
    from core.models import User
    target_user = User.objects.filter(username=username).first()
    if not target_user:
        return JsonResponse({"detail": "User not found."}, status=404)
        
    if user_info.get('role') == 'subadmin':
        if target_user.organization_id != user_info.get('organization_id'):
            return JsonResponse({"detail": "Unauthorized to modify this user."}, status=403)
        if target_user.username == user_info.get('username'):
            return JsonResponse({"detail": "Cannot modify your own account configuration."}, status=400)
            
    data = json.loads(request.body)
    role = data.get("role")
    permissions = data.get("permissions", {})
    
    if user_info.get('role') == 'subadmin' and role not in ['operator', 'viewer']:
        role = target_user.role
        
    updated = db.update_user_role(username, role, permissions)
    return JsonResponse(updated)

@require_login
@require_admin
def delete_user_api(request, username):
    if request.method != "DELETE":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    if username == 'admin':
        return JsonResponse({"detail": "Cannot delete main administrator account."}, status=400)
        
    user_info = request.session.get('user')
    from core.models import User
    target_user = User.objects.filter(username=username).first()
    if not target_user:
        return JsonResponse({"detail": "User not found."}, status=404)
        
    if user_info.get('role') == 'subadmin':
        if target_user.organization_id != user_info.get('organization_id'):
            return JsonResponse({"detail": "Unauthorized to delete this user."}, status=403)
        if target_user.username == user_info.get('username'):
            return JsonResponse({"detail": "Cannot delete your own account."}, status=400)
            
    success = db.delete_user(username)
    return JsonResponse({"status": "success" if success else "failed"})

@require_login
def get_organizations_api(request):
    user_info = request.session.get('user')
    if not user_info or user_info.get('role') != 'admin':
        return JsonResponse({"detail": "Unauthorized"}, status=403)
        
    from core.models import Organization
    orgs = [{"id": o.id, "name": o.name, "created_at": o.created_at.strftime("%Y-%m-%d %H:%M:%S")} for o in Organization.objects.all().order_by('-created_at')]
    return JsonResponse(orgs, safe=False)

@require_login
def create_organization_api(request):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    user_info = request.session.get('user')
    if not user_info or user_info.get('role') != 'admin':
        return JsonResponse({"detail": "Unauthorized"}, status=403)
        
    data = json.loads(request.body)
    org_name = data.get("name", "").strip()
    subadmin_username = data.get("subadmin_username", "").strip()
    subadmin_email = data.get("subadmin_email", "").strip()
    subadmin_password = data.get("subadmin_password", "").strip()
    
    if not org_name or not subadmin_username or not subadmin_email or not subadmin_password:
        return JsonResponse({"detail": "All fields are required."}, status=400)
        
    from core.models import Organization, User
    if Organization.objects.filter(name=org_name).exists():
        return JsonResponse({"detail": f"Organization '{org_name}' already exists."}, status=400)
        
    if User.objects.filter(username=subadmin_username).exists():
        return JsonResponse({"detail": f"Username '{subadmin_username}' already exists."}, status=400)
        
    if User.objects.filter(email=subadmin_email).exists():
        return JsonResponse({"detail": f"Email '{subadmin_email}' is already registered."}, status=400)
        
    org = Organization.objects.create(name=org_name)
    verification_code = generate_code()
    
    subadmin = db.create_user(
        username=subadmin_username,
        email=subadmin_email,
        password_hash=hash_password(subadmin_password),
        role='subadmin',
        permissions={"see": True, "create": True, "edit": True, "delete": True},
        organization_id=org.id,
        is_verified=False,
        verification_code=verification_code
    )
    
    send_verification_email(subadmin_email, verification_code)
    
    return JsonResponse({
        "status": "success",
        "organization": {"id": org.id, "name": org.name},
        "subadmin": subadmin
    })

# -------------------------------------------------------------
# Health Check Endpoint
# -------------------------------------------------------------
def health_check_api(request):
    """Health check endpoint for load balancer probes and uptime monitoring."""
    import django
    from django.db import connection
    import os
    
    views_path = os.path.join(os.path.dirname(__file__), "views.py")
    try:
        with open(views_path, "r", encoding="utf-8") as f:
            lines = len(f.readlines())
    except Exception:
        lines = -1
        
    from django.core.mail import get_connection
    conn = get_connection()
    backend_name = conn.__class__.__name__
    
    health = {
        "status": "healthy",
        "version": "1.0.0",
        "views_line_count": lines,
        "resend_configured": "RESEND_API_KEY" in os.environ,
        "smtp_configured": bool(os.environ.get("EMAIL_USER") and os.environ.get("EMAIL_PASSWORD")),
        "email_backend": backend_name,
        "django_version": django.get_version(),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    }
    
    # Check database connectivity
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        health["database"] = "connected"
    except Exception as e:
        health["status"] = "degraded"
        health["database"] = f"error: {str(e)}"
    
    status_code = 200 if health["status"] == "healthy" else 503
    return JsonResponse(health, status=status_code)

# -------------------------------------------------------------
# DDL Sandbox / Simulation Playground
# -------------------------------------------------------------
@require_login
def sandbox_page(request):
    """Render the DDL Blast Radius simulation sandbox page."""
    user_info = request.session.get('user')
    from core.models import Pipeline
    
    # Scope pipeline list to organization boundary
    if user_info.get('role') == 'admin':
        qs = Pipeline.objects.all().order_by('name')
    else:
        qs = Pipeline.objects.filter(organization_id=user_info.get('organization_id')).order_by('name')
        
    return render(request, 'core/sandbox.html', {
        "pipelines": qs
    })

@require_login
def simulate_ddl_api(request):
    """Simulate proposed DDL scripts on locked contracts and build safe migration paths."""
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    user_info = request.session.get('user')
    data = json.loads(request.body)
    pipeline_id = data.get("pipeline_id")
    ddl_sql = data.get("ddl_sql", "").strip()
    
    target_type = data.get("target_type", "standard")
    
    if not pipeline_id or not ddl_sql:
        return JsonResponse({"detail": "Missing target pipeline ID or SQL DDL content."}, status=400)
        
    from core.models import Pipeline
    p_obj = Pipeline.objects.filter(id=pipeline_id).first()
    if not p_obj:
        return JsonResponse({"detail": "Pipeline not found"}, status=404)
        
    # Scope check
    if user_info.get('role') != 'admin' and p_obj.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)
        
    # Read pipeline contract design
    contract_path = os.path.join(CONTRACTS_DIR, f"{p_obj.table}.yaml")
    if not os.path.exists(contract_path):
        return JsonResponse({"detail": "Active contract specifications not found on server."}, status=400)
        
    try:
        cfg = load_contract(contract_path)
    except Exception as e:
        return JsonResponse({"detail": f"Failed to load YAML contract: {e}"}, status=400)
        
    contract_cols = cfg.get("columns", [])
    
    from core.ddl_parser import simulate_ddl_on_schema, generate_safe_transition_recipe
    
    try:
        # Simulate proposed DDL on original columns list
        simulated_cols, action = simulate_ddl_on_schema(ddl_sql, contract_cols)
    except Exception as e:
        return JsonResponse({"status": "failed", "message": f"DDL parsing/simulation error: {str(e)}"}, status=400)
        
    # Diff check: compare simulated columns state against active contract design
    violations = []
    warnings = []
    
    # 1. Any required contract column missing after DDL simulation?
    contract_map = {col["name"]: col for col in contract_cols}
    simulated_names = set(col["name"] for col in simulated_cols)
    
    for col_name, c_col in contract_map.items():
        if col_name not in simulated_names:
            violations.append(f"CRITICAL: Column '{col_name}' required by downstream contract will be dropped.")
            continue
            
        p_col = next(col for col in simulated_cols if col["name"] == col_name)
        
        # Nullability checks
        c_null = c_col.get("nullable", True)
        p_null = p_col.get("nullable", True)
        if c_null and not p_null:
            violations.append(f"CRITICAL: Column '{col_name}' nullability change: changing from NULL to NOT NULL will fail insertions.")
        elif not c_null and p_null:
            warnings.append(f"Notice: Column '{col_name}' will become nullable (not contract-breaking but increases null exposure).")
            
        # Type checks
        c_type = normalize_type(c_col.get("type", ""))
        p_type = normalize_type(p_col.get("type", ""))
        if c_type != p_type:
            allowed = False
            for drift in c_col.get("allowed_drift", []):
                if normalize_type(drift.get("from")) == c_type and normalize_type(drift.get("to")) == p_type:
                    allowed = True
                    break
            if not allowed:
                violations.append(f"CRITICAL: Column '{col_name}' type mismatch: contract expects '{c_col.get('type')}', DDL alters to '{p_col.get('type')}'")
                
    # 2. Added columns warnings
    simulated_map = {col["name"]: col for col in simulated_cols}
    for col_name, p_col in simulated_map.items():
        if col_name not in contract_map:
            p_null = p_col.get("nullable", True)
            if not p_null:
                warnings.append(f"Notice: New column '{col_name}' is NOT NULL. A default value is required to prevent insertion crashes.")
            else:
                warnings.append(f"Notice: New column '{col_name}' added (fully backward-compatible).")
                
    # Compile results
    compatible = len(violations) == 0
    compliance_rating = "Safe (Compatible)" if compatible else "High Risk (Breaking)"
    recipe = generate_safe_transition_recipe(action, table_type=target_type)
    
    # Render new YAML preview
    import yaml
    new_contract_data = {
        "source": cfg.get("source", {}),
        "columns": [
            {"name": col["name"], "type": col["type"], "nullable": col.get("nullable", True)}
            for col in simulated_cols
        ]
    }
    yaml_preview = yaml.dump(new_contract_data, default_flow_style=False, sort_keys=False)
    
    # Audit log entry
    from core.audit import log_action
    log_action(
        request, 
        'contract.lock', 
        'pipeline_sandbox', 
        pipeline_id, 
        {
            'ddl_action': action.get("type"), 
            'compatible': compatible, 
            'violations': len(violations)
        }
    )
    
    return JsonResponse({
        "status": "success",
        "action": action,
        "compatible": compatible,
        "compliance_rating": compliance_rating,
        "violations": violations,
        "warnings": warnings,
        "recipe": recipe,
        "yaml_preview": yaml_preview
    })


@require_login
def export_dbt_schema_api(request, id):
    """Export active pipeline contracts as fully-compliant dbt schema.yml configurations."""
    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    user_info = request.session.get('user')
    from core.models import Pipeline
    p_obj = Pipeline.objects.filter(id=id).first()
    if not p_obj:
        return JsonResponse({"detail": "Pipeline not found"}, status=404)
        
    # Enforce organization boundary
    if user_info.get('role') != 'admin' and p_obj.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)
        
    # Feature gating check on export
    if user_info.get('role') != 'admin' and p_obj.organization_id:
        from core.models import Organization
        org = Organization.objects.filter(id=p_obj.organization_id).first()
        if org:
            allowed, err = check_feature_permission(org, 'airflow_export')
            if not allowed:
                return JsonResponse({"detail": err}, status=403)
        
    # Load contract design
    contract_path = os.path.join(CONTRACTS_DIR, f"{p_obj.table}.yaml")
    if not os.path.exists(contract_path):
        return JsonResponse({"detail": "Active contract specifications not found on server."}, status=400)
        
    try:
        cfg = load_contract(contract_path)
    except Exception as e:
        return JsonResponse({"detail": f"Failed to load contract specifications: {e}"}, status=400)
        
    columns = cfg.get("columns", [])
    
    # Construct dbt schema structure
    dbt_columns = []
    for col in columns:
        col_name = col.get("name")
        col_type = col.get("type", "unknown")
        nullable = col.get("nullable", True)
        
        col_def = {
            "name": col_name,
            "description": f"Contract baseline type: {col_type}."
        }
        
        # Map not-null assertions
        if not nullable:
            col_def["tests"] = ["not_null"]
            
        dbt_columns.append(col_def)
        
    dbt_model = {
        "name": p_obj.table,
        "description": f"Auto-generated model configuration from Schema Guard pipeline: '{p_obj.name}'.",
        "columns": dbt_columns
    }
    
    dbt_schema = {
        "version": 2,
        "models": [dbt_model]
    }
    
    import yaml
    try:
        dbt_yaml = yaml.dump(dbt_schema, default_flow_style=False, sort_keys=False)
    except Exception as e:
        return JsonResponse({"detail": f"Failed to serialize dbt schema: {e}"}, status=500)
        
    # Log to audit trail
    from core.audit import log_action
    log_action(request, 'contract.lock', 'pipeline_dbt_export', id)
    
    return JsonResponse({
        "status": "success",
        "dbt_yaml": dbt_yaml
    })


@require_login
def download_airflow_operator(request):
    """Download the python module containing Schema Guard Airflow operators/sensors."""
    user_info = request.session.get('user')
    if user_info and user_info.get('role') != 'admin' and user_info.get('organization_id'):
        from core.models import Organization
        org = Organization.objects.filter(id=user_info.get('organization_id')).first()
        if org:
            allowed, err = check_feature_permission(org, 'airflow_export')
            if not allowed:
                return HttpResponse(f"Upgrade Required: {err}", status=403)

    operator_path = os.path.join(os.path.dirname(__file__), 'airflow_operator.py')
    if not os.path.exists(operator_path):
        return HttpResponse("Airflow operator file not found.", status=404)
        
    with open(operator_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type='text/x-python')
        response['Content-Disposition'] = 'attachment; filename="airflow_operator.py"'
        return response


@require_login
def connection_profiles_page(request):
    user_info = request.session.get('user')
    return render(request, 'core/connection_profiles.html', {
        'user': user_info,
    })


@require_login
def connection_profiles_api(request):
    from core.models import ConnectionProfile
    user_info = request.session.get('user')
    org_id = user_info.get('organization_id')
    
    if request.method == "GET":
        if user_info.get('role') == 'admin':
            profiles = ConnectionProfile.objects.all()
        else:
            profiles = ConnectionProfile.objects.filter(organization_id=org_id)
            
        profiles_list = []
        for p in profiles:
            profiles_list.append({
                "id": p.id,
                "name": p.name,
                "db_type": p.db_type,
                "conn_str": mask_connection_string(p.conn_str),
                "created_at": p.created_at.isoformat()
            })
        return JsonResponse({"status": "success", "profiles": profiles_list})
        
    elif request.method == "POST":
        if user_info.get('role') not in ['admin', 'subadmin', 'operator']:
            return JsonResponse({"detail": "Permission Denied: Your account role cannot manage connection profiles."}, status=403)
            
        data = json.loads(request.body)
        name = data.get("name", "").strip()
        db_type = data.get("db_type", "").strip()
        conn_str = data.get("conn_str", "").strip()
        
        if not name or not db_type or not conn_str:
            return JsonResponse({"detail": "All fields (name, db_type, conn_str) are required."}, status=400)
            
        # Feature gating check on database connector engine
        if user_info.get('role') != 'admin' and org_id:
            from core.models import Organization
            org = Organization.objects.filter(id=org_id).first()
            if org:
                allowed, err = check_feature_permission(org, 'db_engine', db_type)
                if not allowed:
                    return JsonResponse({"detail": err}, status=403)
            
        import re
        if not re.match(r'^[a-zA-Z0-9_\-]+$', name):
            return JsonResponse({"detail": "Invalid profile name. Only letters, numbers, underscores, and dashes are allowed."}, status=400)
            
        if ConnectionProfile.objects.filter(name=name, organization_id=org_id).exists():
            return JsonResponse({"detail": f"A connection profile with name '{name}' already exists in your workspace."}, status=400)
            
        try:
            resolved_conn = resolve_connection_string(conn_str, db_type)
            from core.db_connector import test_db_connection
            ok, msg = test_db_connection(db_type, resolved_conn)
            if not ok and not conn_str.startswith("env:"):
                return JsonResponse({"detail": f"Connection test failed: {msg}"}, status=400)
        except Exception as conn_err:
            if not conn_str.startswith("env:"):
                return JsonResponse({"detail": f"Connection test failed: {conn_err}"}, status=400)
                
        p_obj = ConnectionProfile.objects.create(
            name=name,
            db_type=db_type,
            conn_str=encrypt_secret(conn_str),
            organization_id=org_id
        )
        
        from core.audit import log_action
        log_action(request, 'pipeline.create', 'connection_profile', str(p_obj.id))
        
        return JsonResponse({
            "status": "success",
            "profile": {
                "id": p_obj.id,
                "name": p_obj.name,
                "db_type": p_obj.db_type,
                "conn_str": mask_connection_string(p_obj.conn_str),
                "created_at": p_obj.created_at.isoformat()
            }
        })
        
    return HttpResponseNotAllowed(["GET", "POST"])


@require_login
def connection_profile_detail_api(request, id):
    from core.models import ConnectionProfile
    user_info = request.session.get('user')
    org_id = user_info.get('organization_id')
    
    profile = ConnectionProfile.objects.filter(id=id).first()
    if not profile:
        return JsonResponse({"detail": "Connection profile not found."}, status=404)
        
    if user_info.get('role') != 'admin' and profile.organization_id != org_id:
        return JsonResponse({"detail": "Unauthorized"}, status=403)
        
    if request.method == "DELETE":
        if user_info.get('role') not in ['admin', 'subadmin', 'operator']:
            return JsonResponse({"detail": "Permission Denied: Your account role cannot delete connection profiles."}, status=403)
            
        profile.delete()
        
        from core.audit import log_action
        log_action(request, 'pipeline.delete', 'connection_profile', str(id))
        
        return JsonResponse({"status": "success"})
        
    return HttpResponseNotAllowed(["DELETE"])


# -------------------------------------------------------------
# API Key Management APIs (CI/CD Gates & Integrations)
# -------------------------------------------------------------
@require_login
def api_keys_api(request):
    """List or create programmatic API keys for CI/CD gates."""
    user_info = request.session.get('user')
    org_id = user_info.get('organization_id')
    from core.models import ApiKey, Organization
    from core.security import generate_api_key
    
    if request.method == "GET":
        if user_info.get('role') == 'admin':
            keys = ApiKey.objects.all()
        else:
            keys = ApiKey.objects.filter(organization_id=org_id)
            
        data = [{
            "id": k.id,
            "key_id": k.key_id,
            "name": k.name,
            "created_by": k.created_by,
            "is_active": k.is_active,
            "last_used_at": k.last_used_at.strftime("%Y-%m-%d %H:%M:%S") if k.last_used_at else None,
            "created_at": k.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        } for k in keys]
        return JsonResponse({"status": "success", "api_keys": data})
        
    elif request.method == "POST":
        if user_info.get('role') not in ['admin', 'subadmin']:
            return JsonResponse({"detail": "Permission denied: Only admins and subadmins can generate API keys."}, status=403)
            
        body = json.loads(request.body) if request.body else {}
        name = body.get("name", "CI/CD Gate Key").strip()
        
        org = Organization.objects.filter(id=org_id).first()
        if not org and user_info.get('role') == 'admin':
            org = Organization.objects.first()
            
        if not org:
            return JsonResponse({"detail": "No organization found to bind API key."}, status=400)
            
        # Feature gating check on API keys
        if user_info.get('role') != 'admin' and org:
            allowed, err = check_feature_permission(org, 'api_keys')
            if not allowed:
                return JsonResponse({"detail": err}, status=403)
            
        raw_key, key_id, key_hash = generate_api_key()
        api_key_obj = ApiKey.objects.create(
            key_id=key_id,
            key_hash=key_hash,
            name=name,
            organization=org,
            created_by=user_info.get('username', 'admin')
        )
        
        from core.audit import log_action
        log_action(request, 'apikey.create', 'api_key', str(api_key_obj.id), {'name': name, 'key_id': key_id})
        
        return JsonResponse({
            "status": "success",
            "raw_key": raw_key,
            "key_id": key_id,
            "name": name,
            "message": "Copy this secret API key now. It will not be shown again."
        })
        
    return HttpResponseNotAllowed(["GET", "POST"])


@require_login
def api_key_detail_api(request, key_id):
    """Revoke an active API key."""
    user_info = request.session.get('user')
    org_id = user_info.get('organization_id')
    from core.models import ApiKey
    
    key_obj = ApiKey.objects.filter(key_id=key_id).first()
    if not key_obj:
        return JsonResponse({"detail": "API key not found."}, status=404)
        
    if user_info.get('role') != 'admin' and key_obj.organization_id != org_id:
        return JsonResponse({"detail": "Unauthorized"}, status=403)
        
    if request.method == "DELETE":
        if user_info.get('role') not in ['admin', 'subadmin']:
            return JsonResponse({"detail": "Permission denied."}, status=403)
            
        key_obj.is_active = False
        key_obj.delete()
        
        from core.audit import log_action
        log_action(request, 'apikey.revoke', 'api_key', key_id)
        return JsonResponse({"status": "success", "message": "API key revoked successfully."})
        
    return HttpResponseNotAllowed(["DELETE"])


# =============================================================
# Step 1: Stripe Billing & Subscription Management
# =============================================================
import stripe
stripe.api_key = getattr(settings, 'STRIPE_SECRET_KEY', 'sk_test_placeholder')

@require_login
def create_checkout_session_api(request):
    """
    Creates a Stripe Checkout Session for upgrading organization plan.
    Accepts JSON: { "plan": "pro" } or { "plan": "enterprise" }
    Returns: { "url": "<stripe_checkout_url>", "session_id": "cs_..." }
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body) if request.body else {}
    except Exception:
        data = {}

    plan = data.get("plan", "pro").lower()
    if plan not in ["pro", "enterprise"]:
        return JsonResponse({"detail": "Invalid plan. Choose 'pro' or 'enterprise'."}, status=400)

    user_info = request.session.get('user', {})
    from core.models import User, Organization
    user = User.objects.filter(username=user_info.get('username')).first()
    if not user:
        return JsonResponse({"detail": "User not found."}, status=404)

    org = user.organization
    if not org:
        org = Organization.objects.create(name=f"{user.username}'s Workspace", plan='free', max_pipelines=5)
        user.organization = org
        user.save(update_fields=['organization'])
        user_info['organization_id'] = org.id
        request.session['user'] = user_info

    price_id = getattr(settings, 'STRIPE_PRO_PRICE_ID', 'price_pro_monthly') if plan == 'pro' else getattr(settings, 'STRIPE_ENTERPRISE_PRICE_ID', 'price_enterprise_monthly')
    secret_key = getattr(settings, 'STRIPE_SECRET_KEY', '')
    is_live_key = secret_key and not secret_key.startswith('sk_test_placeholder')

    success_url = request.build_absolute_uri('/dashboard?billing=success&session_id={CHECKOUT_SESSION_ID}')
    cancel_url = request.build_absolute_uri('/pricing?billing=cancelled')

    if is_live_key:
        try:
            if not org.stripe_customer_id:
                customer = stripe.Customer.create(
                    email=user.email,
                    name=org.name,
                    metadata={"org_id": str(org.id), "username": user.username}
                )
                org.stripe_customer_id = customer.id
                org.save(update_fields=['stripe_customer_id'])

            session = stripe.checkout.Session.create(
                customer=org.stripe_customer_id,
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={
                    'org_id': str(org.id),
                    'plan': plan,
                    'username': user.username
                }
            )
            log_action(request, 'billing.checkout_created', 'organization', str(org.id), {
                'plan': plan, 'session_id': session.id
            })
            return JsonResponse({"status": "success", "url": session.url, "session_id": session.id})
        except Exception as e:
            logger.error(f"Stripe Checkout creation error: {e}")
            return JsonResponse({"detail": f"Stripe error: {str(e)}"}, status=400)
    else:
        # Development / Sandbox simulation mode when live Stripe credentials are placeholder
        simulated_session_id = f"cs_test_simulated_{org.id}_{plan}"
        simulated_url = request.build_absolute_uri(f"/dashboard?billing=success&session_id={simulated_session_id}&simulated=true&plan={plan}")
        log_action(request, 'billing.checkout_created', 'organization', str(org.id), {
            'plan': plan, 'simulated': True
        })
        return JsonResponse({
            "status": "success",
            "url": simulated_url,
            "session_id": simulated_session_id,
            "simulated": True,
            "message": "Development mode: Stripe simulation link generated."
        })


@require_login
def create_customer_portal_api(request):
    """
    Creates a Stripe Billing Customer Portal session for subscription cancellation/management.
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    from core.models import User
    user = User.objects.filter(username=user_info.get('username')).first()
    if not user or not user.organization:
        return JsonResponse({"detail": "Organization not found."}, status=404)

    org = user.organization
    secret_key = getattr(settings, 'STRIPE_SECRET_KEY', '')
    is_live_key = secret_key and not secret_key.startswith('sk_test_placeholder')

    if is_live_key and org.stripe_customer_id:
        try:
            portal_session = stripe.billing_portal.Session.create(
                customer=org.stripe_customer_id,
                return_url=request.build_absolute_uri('/dashboard')
            )
            return JsonResponse({"status": "success", "url": portal_session.url})
        except Exception as e:
            logger.error(f"Stripe Portal creation error: {e}")
            return JsonResponse({"detail": f"Portal error: {str(e)}"}, status=400)
    else:
        return JsonResponse({
            "status": "success",
            "url": request.build_absolute_uri('/pricing'),
            "simulated": True,
            "message": "No active live Stripe customer found. Redirecting to pricing."
        })


def downgrade_plan_api(request):
    """
    Downgrades the user's organization to the Developer Free plan.
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    from core.models import User
    user = User.objects.filter(username=user_info.get('username')).first()
    if not user or not user.organization:
        return JsonResponse({"detail": "Organization not found."}, status=404)

    org = user.organization
    org.plan = 'free'
    org.max_pipelines = 5
    org.save()

    return JsonResponse({
        "status": "success",
        "message": "Organization has been downgraded to the Developer Free plan.",
        "plan": "free",
        "max_pipelines": 5
    })


@csrf_exempt
def stripe_webhook(request):
    """
    Stripe Webhook processor handling subscription lifecycle events:
    - checkout.session.completed: Upgrades organization plan & max_pipelines
    - customer.subscription.updated: Updates subscription state
    - customer.subscription.deleted: Downgrades back to free plan
    """
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE', '')
    webhook_secret = getattr(settings, 'STRIPE_WEBHOOK_SECRET', '')

    event = None
    if webhook_secret and not webhook_secret.startswith('whsec_placeholder'):
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        except Exception as e:
            logger.error(f"Stripe Webhook signature failure: {e}")
            return JsonResponse({"error": f"Invalid signature: {str(e)}"}, status=400)
    else:
        try:
            event = json.loads(payload.decode('utf-8'))
        except Exception as e:
            return JsonResponse({"error": f"Invalid payload: {str(e)}"}, status=400)

    event_type = event.get('type')
    event_data = event.get('data', {}).get('object', {})

    from core.models import Organization
    quotas = getattr(settings, 'PLAN_QUOTAS', {
        'free': {'max_pipelines': 5},
        'pro': {'max_pipelines': 50},
        'enterprise': {'max_pipelines': 1000},
    })

    if event_type == 'checkout.session.completed':
        metadata = event_data.get('metadata', {})
        org_id = metadata.get('org_id')
        plan = metadata.get('plan', 'pro')
        customer_id = event_data.get('customer')
        subscription_id = event_data.get('subscription')

        org = None
        if org_id:
            org = Organization.objects.filter(id=org_id).first()
        elif customer_id:
            org = Organization.objects.filter(stripe_customer_id=customer_id).first()

        if org:
            org.plan = plan
            org.max_pipelines = quotas.get(plan, {}).get('max_pipelines', 50)
            if customer_id:
                org.stripe_customer_id = customer_id
            if subscription_id:
                org.stripe_subscription_id = subscription_id
            org.subscription_status = 'active'
            org.save()
            log_action(request, 'billing.subscription_updated', 'organization', str(org.id), {
                'plan': plan,
                'max_pipelines': org.max_pipelines,
                'subscription_id': subscription_id
            })

    elif event_type == 'customer.subscription.updated':
        customer_id = event_data.get('customer')
        sub_status = event_data.get('status', 'active')
        org = Organization.objects.filter(stripe_customer_id=customer_id).first()
        if org:
            org.subscription_status = sub_status
            org.save(update_fields=['subscription_status'])
            log_action(request, 'billing.subscription_updated', 'organization', str(org.id), {
                'status': sub_status
            })

    elif event_type == 'customer.subscription.deleted':
        customer_id = event_data.get('customer')
        org = Organization.objects.filter(stripe_customer_id=customer_id).first()
        if org:
            org.plan = 'free'
            org.max_pipelines = quotas.get('free', {}).get('max_pipelines', 5)
            org.subscription_status = 'canceled'
            org.save()
            log_action(request, 'billing.subscription_cancelled', 'organization', str(org.id), {
                'plan': 'free'
            })

    return JsonResponse({"status": "handled", "type": event_type})


@csrf_exempt
@require_login
def submit_qr_payment_api(request):
    """
    Validates and processes a QR code / UPI payment submission.
    Keeps plan unchanged as pending, saves screenshot, and dispatches
    approval email with 1-click approval link to administrator.
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    username = user_info.get('username')
    from core.models import User, Organization, PaymentTransaction

    user = User.objects.filter(username=username).first()
    if not user:
        return JsonResponse({"detail": "User not found."}, status=404)

    try:
        data = json.loads(request.body)
    except Exception:
        return JsonResponse({"detail": "Invalid JSON payload."}, status=400)

    plan = data.get("plan", "pro").strip().lower()
    if plan not in ["pro", "enterprise"]:
        return JsonResponse({"detail": "Invalid plan. Choose 'pro' or 'enterprise'."}, status=400)

    transaction_id = data.get("transaction_id", "").strip().upper()
    if not transaction_id or len(transaction_id) < 6:
        return JsonResponse({
            "detail": "Please enter a valid UPI Reference / UTR Number (minimum 6 digits)."
        }, status=400)

    screenshot_data = data.get("screenshot_data", "").strip()
    if not screenshot_data:
        return JsonResponse({
            "detail": "Please upload a screenshot of your successful transaction."
        }, status=400)

    # Check if transaction ID already used
    if PaymentTransaction.objects.filter(transaction_id=transaction_id).exists():
        return JsonResponse({
            "detail": f"Transaction ID '{transaction_id}' has already been registered."
        }, status=400)

    org = user.organization
    if not org:
        org = Organization.objects.create(name=f"{user.username}'s Workspace", plan='free', max_pipelines=5)
        user.organization = org
        user.save(update_fields=['organization'])

    quotas = getattr(settings, 'PLAN_QUOTAS', {
        'free': {'max_pipelines': 5},
        'pro': {'max_pipelines': 50},
        'enterprise': {'max_pipelines': 1000},
    })

    amount = data.get("amount") or ("₹3,999 ($49/mo)" if plan == 'pro' else "₹15,999 ($199/mo)")
    notes = data.get("notes", "").strip()
    approval_token = secrets.token_urlsafe(32)

    # Record Payment Transaction in 'pending' status — PLAN STAYS AS IS!
    payment = PaymentTransaction.objects.create(
        transaction_id=transaction_id,
        organization=org,
        user=user,
        plan=plan,
        amount=amount,
        payment_method="UPI_QR",
        status="pending",
        screenshot_data=screenshot_data,
        approval_token=approval_token,
        notes=notes
    )

    # Build 1-click approve & reject links
    approve_url = request.build_absolute_uri(f"/api/billing/approve-payment?token={approval_token}")
    reject_url = request.build_absolute_uri(f"/api/billing/reject-payment?token={approval_token}")
    view_screenshot_url = request.build_absolute_uri(f"/api/billing/transactions/{payment.id}/screenshot")
    if not settings.DEBUG and '127.0.0.1' not in approve_url and 'localhost' not in approve_url:
        approve_url = approve_url.replace('http://', 'https://', 1)
        reject_url = reject_url.replace('http://', 'https://', 1)
        view_screenshot_url = view_screenshot_url.replace('http://', 'https://', 1)

    # Dispatch email to Admin with attachment
    admin_recipient = "anusolanki2645@gmail.com"
    subject = f"🔔 [Action Required] Payment Approval: {user.username} ({plan.upper()} - {amount})"

    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body style="font-family: Arial, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 24px; margin: 0;">
      <div style="max-width: 580px; margin: 0 auto; background: #1e293b; border-radius: 12px; border: 1px solid rgba(56, 189, 248, 0.3); padding: 28px; box-shadow: 0 8px 30px rgba(0,0,0,0.5);">
        <h2 style="margin: 0 0 16px 0; color: #38bdf8; font-size: 22px;">Schema Guard — Payment Verification</h2>
        <p style="font-size: 14px; color: #cbd5e1; line-height: 1.5;">
          A user has submitted a UPI payment proof requesting a workspace upgrade. Review the details below and click <strong>Approve</strong> to assign permissions.
        </p>

        <div style="background: #0f172a; border-radius: 8px; padding: 16px 20px; margin: 20px 0; font-size: 14px; line-height: 1.8;">
          <div><strong style="color: #94a3b8;">User:</strong> <span style="color: #ffffff;">{user.username} ({user.email})</span></div>
          <div><strong style="color: #94a3b8;">Organization:</strong> <span style="color: #ffffff;">{org.name}</span></div>
          <div><strong style="color: #94a3b8;">Requested Plan:</strong> <span style="color: #a855f7; font-weight: bold;">{plan.upper()} ({quotas.get(plan, {}).get('max_pipelines', 50)} Pipelines)</span></div>
          <div><strong style="color: #94a3b8;">Amount:</strong> <span style="color: #38bdf8; font-weight: bold;">{amount}</span></div>
          <div><strong style="color: #94a3b8;">UPI UTR / Txn ID:</strong> <span style="font-family: monospace; background: rgba(56,189,248,0.15); color: #38bdf8; padding: 2px 6px; border-radius: 4px; font-weight: bold;">{transaction_id}</span></div>
          {f'<div><strong style="color: #94a3b8;">Notes:</strong> <span style="color: #e2e8f0;">{notes}</span></div>' if notes else ''}
        </div>

        <div style="margin: 24px 0 16px 0; text-align: center;">
          <a href="{approve_url}" style="display: inline-block; background: #16a34a; color: #ffffff; text-decoration: none; font-weight: bold; font-size: 15px; padding: 14px 28px; border-radius: 8px; box-shadow: 0 4px 15px rgba(22, 163, 74, 0.4); margin-right: 12px;">
            ✅ Approve & Activate {plan.upper()}
          </a>
          <a href="{reject_url}" style="display: inline-block; background: #dc2626; color: #ffffff; text-decoration: none; font-weight: bold; font-size: 14px; padding: 14px 20px; border-radius: 8px;">
            ❌ Reject
          </a>
        </div>
        <p style="text-align: center; font-size: 12px; color: #64748b; margin-top: 8px;">
          Clicking "Approve" will immediately unlock all {plan.upper()} features for {user.username}'s workspace.
        </p>

        <hr style="border: none; border-top: 1px solid rgba(255, 255, 255, 0.1); margin: 24px 0;" />
        
        <p style="font-size: 13px; color: #94a3b8;">
          📎 Payment Screenshot is attached to this email.<br>
          🔍 Or view proof directly in browser: <a href="{view_screenshot_url}" style="color: #38bdf8; text-decoration: underline;">View Screenshot Proof</a>
        </p>
      </div>
    </body>
    </html>
    """

    plain_msg = f"""Schema Guard Payment Request:
User: {user.username} ({user.email})
Organization: {org.name}
Plan: {plan.upper()} ({amount})
Transaction ID: {transaction_id}

Approve Link: {approve_url}
Reject Link: {reject_url}
Screenshot: {view_screenshot_url}
"""

    try:
        from django.core.mail import EmailMultiAlternatives
        import base64
        msg = EmailMultiAlternatives(subject, plain_msg, settings.DEFAULT_FROM_EMAIL, [admin_recipient])
        msg.attach_alternative(html_body, 'text/html')
        if screenshot_data:
            raw_b64 = screenshot_data.split(',', 1)[1] if ',' in screenshot_data else screenshot_data
            msg.attach('transaction_proof.jpg', base64.b64decode(raw_b64), 'image/jpeg')
        msg.send(fail_silently=False)
    except Exception as email_err:
        logger.error(f"Failed to send payment approval email: {email_err}")

    # Log to immutable audit trail
    from core.audit import log_action
    log_action(request, 'billing.qr_payment_submitted', 'organization', str(org.id), {
        'plan': plan,
        'transaction_id': transaction_id,
        'amount': amount,
        'status': 'pending'
    })

    return JsonResponse({
        "status": "pending",
        "message": "your request is confirm in 1 hour \nIf you need access now please contact on this mail anusolanki2645@gmail.com",
        "transaction_id": transaction_id
    })


def approve_payment_api(request):
    """
    Administrator 1-click email approval link.
    Validates token, activates plan on Organization, and sends confirmation to user.
    """
    token = request.GET.get('token', '').strip()
    if not token:
        return HttpResponse("<h1>Missing approval token.</h1>", status=400)

    from core.models import PaymentTransaction, Organization
    from django.utils import timezone
    payment = PaymentTransaction.objects.filter(approval_token=token).first()
    if not payment:
        return HttpResponse("<h1>Invalid or expired approval token.</h1>", status=404)

    if payment.status == 'approved':
        return HttpResponse(f"""
        <!DOCTYPE html>
        <html><head><title>Already Approved</title></head>
        <body style="background: #0f172a; color: #fff; font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0;">
          <div style="background: #1e293b; padding: 36px; border-radius: 12px; text-align: center; max-width: 460px; border: 1px solid rgba(56, 189, 248, 0.3);">
            <h2 style="color: #38bdf8;">Already Approved</h2>
            <p>Transaction <code>{payment.transaction_id}</code> was already approved and activated for <b>{payment.organization.name}</b>.</p>
            <a href="/dashboard" style="display: inline-block; background: #38bdf8; color: #020617; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: bold; margin-top: 12px;">Go to Dashboard</a>
          </div>
        </body></html>
        """)

    quotas = getattr(settings, 'PLAN_QUOTAS', {
        'free': {'max_pipelines': 5},
        'pro': {'max_pipelines': 50},
        'enterprise': {'max_pipelines': 1000},
    })

    # Upgrade Organization Plan
    org = payment.organization
    org.plan = payment.plan
    org.max_pipelines = quotas.get(payment.plan, {}).get('max_pipelines', 50 if payment.plan == 'pro' else 1000)
    org.subscription_status = 'active'
    org.save(update_fields=['plan', 'max_pipelines', 'subscription_status'])

    # Mark transaction as approved
    payment.status = 'approved'
    payment.approved_at = timezone.now()
    payment.save(update_fields=['status', 'approved_at'])

    # Log to audit trail
    from core.audit import log_action
    log_action(request, 'billing.subscription_updated', 'organization', str(org.id), {
        'plan': payment.plan,
        'approved_by': 'admin_email_link',
        'transaction_id': payment.transaction_id
    })

    # Notify User by Email
    if payment.user and payment.user.email:
        user_subject = f"🎉 Schema Guard: Your {payment.plan.upper()} Workspace is Active!"
        dash_url = request.build_absolute_uri('/dashboard')
        if not settings.DEBUG and '127.0.0.1' not in dash_url:
            dash_url = dash_url.replace('http://', 'https://', 1)

        user_html = f"""
        <div style="font-family: Arial, sans-serif; background: #0f172a; color: #f8fafc; padding: 24px;">
          <div style="max-width: 520px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 24px; border: 1px solid rgba(34, 197, 94, 0.4);">
            <h2 style="color: #4ade80; margin-top: 0;">🎉 Workspace Upgraded to {payment.plan.upper()}!</h2>
            <p>Hello <strong>{payment.user.username}</strong>,</p>
            <p>Your UPI payment (Transaction ID: <code>{payment.transaction_id}</code>) has been confirmed and verified.</p>
            <p>Your workspace <strong>{org.name}</strong> now has full access to:</p>
            <ul>
              <li>Up to <strong>{org.max_pipelines} Monitored Pipelines</strong></li>
              <li>Snowflake, Databricks, SQL Server & Cloud Connectors</li>
              <li>High-frequency minute audits</li>
              <li>Unlimited CI/CD Gate API Keys</li>
              <li>AI Root-Cause Diagnostics & SQL repair generator</li>
              <li>Native Airflow Operator & dbt schema exports</li>
            </ul>
            <div style="text-align: center; margin: 24px 0;">
              <a href="{dash_url}" style="background: #22c55e; color: #fff; text-decoration: none; font-weight: bold; padding: 12px 24px; border-radius: 8px; display: inline-block;">Open Your Dashboard ⚡</a>
            </div>
            <p style="color: #94a3b8; font-size: 12px;">If you have any questions, reach us anytime at anusolanki2645@gmail.com</p>
          </div>
        </div>
        """
        send_email_helper(user_subject, f"Your Schema Guard {payment.plan.upper()} workspace is now active! Visit: {dash_url}", payment.user.email, html_message=user_html)

    return HttpResponse(f"""
    <!DOCTYPE html>
    <html><head><title>Payment Approved - Schema Guard</title></head>
    <body style="background: #0f172a; color: #fff; font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0;">
      <div style="background: #1e293b; padding: 40px; border-radius: 12px; text-align: center; max-width: 500px; border: 1px solid rgba(34, 197, 94, 0.4); box-shadow: 0 10px 40px rgba(0,0,0,0.5);">
        <div style="font-size: 52px; margin-bottom: 12px;">✅</div>
        <h2 style="color: #4ade80; margin-bottom: 8px;">Payment Approved!</h2>
        <p style="color: #94a3b8; margin-bottom: 20px;">The workspace has been successfully upgraded and user notified.</p>
        <div style="background: #0f172a; padding: 16px; border-radius: 8px; text-align: left; font-size: 14px; line-height: 1.8; margin-bottom: 24px;">
          <div><b>Organization:</b> <span style="color: #38bdf8;">{org.name}</span></div>
          <div><b>User:</b> <span>{payment.user.username if payment.user else 'Unknown'}</span></div>
          <div><b>Plan:</b> <span style="color: #a855f7; font-weight: bold;">{payment.plan.upper()} ({org.max_pipelines} Pipelines)</span></div>
          <div><b>Transaction ID:</b> <code>{payment.transaction_id}</code></div>
          <div><b>Amount:</b> <span>{payment.amount}</span></div>
        </div>
        <a href="/dashboard" style="display: inline-block; background: #22c55e; color: #ffffff; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold;">Return to Dashboard</a>
      </div>
    </body></html>
    """)


def reject_payment_api(request):
    """Administrator 1-click email reject link."""
    token = request.GET.get('token', '').strip()
    if not token:
        return HttpResponse("<h1>Missing rejection token.</h1>", status=400)

    from core.models import PaymentTransaction
    payment = PaymentTransaction.objects.filter(approval_token=token).first()
    if not payment:
        return HttpResponse("<h1>Invalid or expired token.</h1>", status=404)

    payment.status = 'rejected'
    payment.save(update_fields=['status'])

    return HttpResponse(f"""
    <!DOCTYPE html>
    <html><head><title>Payment Request Rejected</title></head>
    <body style="background: #0f172a; color: #fff; font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0;">
      <div style="background: #1e293b; padding: 36px; border-radius: 12px; text-align: center; max-width: 460px; border: 1px solid rgba(239, 68, 68, 0.4);">
        <div style="font-size: 52px; margin-bottom: 12px;">❌</div>
        <h2 style="color: #f87171;">Payment Request Rejected</h2>
        <p>Transaction <code>{payment.transaction_id}</code> for workspace <b>{payment.organization.name}</b> has been marked as rejected.</p>
        <a href="/dashboard" style="display: inline-block; background: #64748b; color: #ffffff; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: bold; margin-top: 12px;">Return to Dashboard</a>
      </div>
    </body></html>
    """)



@require_login
def list_payment_transactions_api(request):
    """List payment transactions (admin sees all, users see their org's)."""
    user_info = request.session.get('user', {})
    from core.models import PaymentTransaction
    if user_info.get('role') == 'admin':
        txs = PaymentTransaction.objects.all().select_related('organization', 'user')
    else:
        txs = PaymentTransaction.objects.filter(organization_id=user_info.get('organization_id')).select_related('organization', 'user')

    data = [{
        "id": t.id,
        "transaction_id": t.transaction_id,
        "organization": t.organization.name if t.organization else "Workspace",
        "user": t.user.username if t.user else "Unknown",
        "plan": t.plan.upper(),
        "amount": t.amount,
        "status": t.status,
        "payment_method": t.payment_method,
        "created_at": t.created_at.strftime("%Y-%m-%d %H:%M:%S")
    } for t in txs]
    return JsonResponse({"status": "success", "transactions": data})


def transaction_screenshot_api(request, id):
    """View payment screenshot proof directly."""
    from core.models import PaymentTransaction
    tx = PaymentTransaction.objects.filter(id=id).first()
    if not tx or not tx.screenshot_data:
        return HttpResponse("<h1>No screenshot available</h1>", status=404)

    import base64
    raw_data = tx.screenshot_data
    if ',' in raw_data:
        header, b64_str = raw_data.split(',', 1)
        mime = header.split(';')[0].replace('data:', '')
    else:
        b64_str = raw_data
        mime = 'image/jpeg'
    img_bytes = base64.b64decode(b64_str)
    return HttpResponse(img_bytes, content_type=mime)



# =============================================================
# Step 2: GitHub & Google OAuth Authentication
# =============================================================
import secrets
import urllib.parse
import urllib.request

def oauth_github_login(request):
    """Initiates GitHub OAuth flow or opens mock dev login if keys unconfigured."""
    client_id = getattr(settings, 'GITHUB_CLIENT_ID', '')
    state = secrets.token_urlsafe(32)
    request.session['oauth_state'] = state
    redirect_uri = request.build_absolute_uri('/auth/github/callback')
    if not settings.DEBUG and redirect_uri.startswith('http://') and '127.0.0.1' not in redirect_uri and 'localhost' not in redirect_uri:
        redirect_uri = redirect_uri.replace('http://', 'https://', 1)

    if not client_id:
        return render(request, 'core/oauth_fallback.html', {
            'provider': 'GitHub',
            'state': state,
            'callback_url': f'/auth/github/callback?code=mock_github_code&state={state}'
        })

    auth_url = f"https://github.com/login/oauth/authorize?client_id={client_id}&redirect_uri={urllib.parse.quote(redirect_uri)}&scope=read:user,user:email&state={state}"
    return redirect(auth_url)


def oauth_github_callback(request):
    """Callback for GitHub OAuth authorization code."""
    state = request.GET.get('state')
    saved_state = request.session.get('oauth_state')
    if not state or state != saved_state:
        return redirect('/?error_message=Invalid OAuth state session. Please try again.')

    code = request.GET.get('code')
    if not code:
        return redirect('/?error_message=No authorization code provided by GitHub.')

    client_id = getattr(settings, 'GITHUB_CLIENT_ID', '')
    client_secret = getattr(settings, 'GITHUB_CLIENT_SECRET', '')

    if code == 'mock_github_code' or not client_id:
        mock_username = request.GET.get('mock_user', 'github_dev')
        mock_email = request.GET.get('mock_email', 'dev@github.example.com')
        gh_user = {'login': mock_username, 'name': 'GitHub Developer', 'email': mock_email}
    else:
        try:
            token_url = "https://github.com/login/oauth/access_token"
            token_data = urllib.parse.urlencode({
                'client_id': client_id,
                'client_secret': client_secret,
                'code': code
            }).encode('utf-8')
            token_req = urllib.request.Request(
                token_url,
                data=token_data,
                headers={'Accept': 'application/json', 'User-Agent': 'SchemaGuardApp'}
            )
            with urllib.request.urlopen(token_req, timeout=10) as resp:
                token_res = json.loads(resp.read().decode('utf-8'))

            access_token = token_res.get('access_token')
            if not access_token:
                return redirect(f"/?error_message=GitHub authentication failed: {token_res.get('error_description', 'No access token')}")

            profile_req = urllib.request.Request(
                "https://api.github.com/user",
                headers={'Authorization': f"Bearer {access_token}", 'User-Agent': 'SchemaGuardApp'}
            )
            with urllib.request.urlopen(profile_req, timeout=10) as resp:
                gh_user = json.loads(resp.read().decode('utf-8'))

            if not gh_user.get('email'):
                emails_req = urllib.request.Request(
                    "https://api.github.com/user/emails",
                    headers={'Authorization': f"Bearer {access_token}", 'User-Agent': 'SchemaGuardApp'}
                )
                with urllib.request.urlopen(emails_req, timeout=10) as resp:
                    emails = json.loads(resp.read().decode('utf-8'))
                    primary = next((e['email'] for e in emails if e.get('primary') and e.get('verified')), None)
                    if not primary and emails:
                        primary = emails[0]['email']
                    gh_user['email'] = primary
        except Exception as e:
            logger.error(f"GitHub OAuth request error: {e}")
            return redirect(f"/?error_message=GitHub OAuth error: {str(e)}")

    return _complete_oauth_login(request, provider='github', profile=gh_user)


def oauth_google_login(request):
    """Initiates Google OAuth flow or opens mock dev login if keys unconfigured."""
    client_id = getattr(settings, 'GOOGLE_CLIENT_ID', '')
    state = secrets.token_urlsafe(32)
    request.session['oauth_state'] = state
    redirect_uri = request.build_absolute_uri('/auth/google/callback')
    if not settings.DEBUG and redirect_uri.startswith('http://') and '127.0.0.1' not in redirect_uri and 'localhost' not in redirect_uri:
        redirect_uri = redirect_uri.replace('http://', 'https://', 1)

    if not client_id:
        return render(request, 'core/oauth_fallback.html', {
            'provider': 'Google',
            'state': state,
            'callback_url': f'/auth/google/callback?code=mock_google_code&state={state}'
        })

    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'access_type': 'online'
    }
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
    return redirect(auth_url)


def oauth_google_callback(request):
    """Callback for Google OAuth authorization code."""
    state = request.GET.get('state')
    saved_state = request.session.get('oauth_state')
    if not state or state != saved_state:
        return redirect('/?error_message=Invalid OAuth state session. Please try again.')

    code = request.GET.get('code')
    if not code:
        return redirect('/?error_message=No authorization code provided by Google.')

    client_id = getattr(settings, 'GOOGLE_CLIENT_ID', '')
    client_secret = getattr(settings, 'GOOGLE_CLIENT_SECRET', '')
    redirect_uri = request.build_absolute_uri('/auth/google/callback')
    if not settings.DEBUG and redirect_uri.startswith('http://') and '127.0.0.1' not in redirect_uri and 'localhost' not in redirect_uri:
        redirect_uri = redirect_uri.replace('http://', 'https://', 1)

    if code == 'mock_google_code' or not client_id:
        mock_email = request.GET.get('mock_email', 'dev@google.example.com')
        mock_name = request.GET.get('mock_name', 'Google Developer')
        g_user = {'email': mock_email, 'name': mock_name, 'sub': 'google_123456'}
    else:
        try:
            token_url = "https://oauth2.googleapis.com/token"
            token_data = urllib.parse.urlencode({
                'client_id': client_id,
                'client_secret': client_secret,
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': redirect_uri
            }).encode('utf-8')

            token_req = urllib.request.Request(
                token_url,
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'SchemaGuardApp'}
            )
            with urllib.request.urlopen(token_req, timeout=10) as resp:
                token_res = json.loads(resp.read().decode('utf-8'))

            access_token = token_res.get('access_token')
            if not access_token:
                return redirect("/?error_message=Google authentication failed: No access token.")

            info_req = urllib.request.Request(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={'Authorization': f"Bearer {access_token}", 'User-Agent': 'SchemaGuardApp'}
            )
            with urllib.request.urlopen(info_req, timeout=10) as resp:
                g_user = json.loads(resp.read().decode('utf-8'))
        except Exception as e:
            logger.error(f"Google OAuth request error: {e}")
            return redirect(f"/?error_message=Google OAuth error: {str(e)}")

    return _complete_oauth_login(request, provider='google', profile=g_user)


def _complete_oauth_login(request, provider: str, profile: dict):
    """Shared handler to resolve/create user account and log into session."""
    from core.models import User, Organization

    try:
        email = profile.get('email')
        if not email:
            raw_id = profile.get('login') or profile.get('sub') or 'developer'
            email = f"{raw_id}@{provider}.user"

        user = User.objects.filter(email=email).first()

        if not user:
            base_username = profile.get('login') or email.split('@')[0]
            clean_user = "".join(c for c in base_username if c.isalnum() or c in ['_', '-'])[:140] or f"{provider}_user"
            username = clean_user
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{clean_user}_{counter}"
                counter += 1

            org_name = f"{username}'s Workspace"
            org_counter = 1
            while Organization.objects.filter(name=org_name).exists():
                org_name = f"{username}'s Workspace {org_counter}"
                org_counter += 1

            org = Organization.objects.create(name=org_name, plan='free', max_pipelines=5)

            user = User.objects.create(
                username=username,
                email=email,
                full_name=profile.get('name') or username,
                avatar_data=profile.get('picture') or profile.get('avatar_url') or '',
                password_hash=hash_password(secrets.token_hex(20)),
                role='subadmin',
                permissions={"see": True, "create": True, "edit": True, "delete": True},
                organization=org,
                is_verified=True
            )
        else:
            update_fields = []
            if not user.is_verified:
                user.is_verified = True
                update_fields.append('is_verified')
            if not getattr(user, 'full_name', '') and profile.get('name'):
                user.full_name = profile.get('name')
                update_fields.append('full_name')
            if not getattr(user, 'avatar_data', '') and (profile.get('picture') or profile.get('avatar_url')):
                user.avatar_data = profile.get('picture') or profile.get('avatar_url')
                update_fields.append('avatar_data')
            if update_fields:
                user.save(update_fields=update_fields)

        request.session['user'] = build_user_session_dict(user)

        log_action(request, 'user.oauth_login', 'user', user.username, {
            'provider': provider, 'email': user.email
        })
        return redirect('dashboard')
    except (OperationalError, DatabaseError) as db_err:
        logger.error(f"Database error during OAuth login: {db_err}")
        return redirect('/?error_message=Database connection error: Could not reach database server during OAuth sign-in. Please try again.')
    except Exception as e:
        logger.error(f"Unexpected error during OAuth login: {e}")
        return redirect(f'/?error_message=OAuth sign-in error: {str(e)}')


# =============================================================
# Step 3: Dedicated Pricing & Marketing Showcase View
# =============================================================
def pricing_page(request):
    """Public pricing showcase and subscription selection page."""
    user_info = request.session.get('user')
    current_plan = 'free'
    org = None

    if user_info:
        from core.models import User
        user = User.objects.filter(username=user_info.get('username')).first()
        if user and user.organization:
            org = user.organization
            current_plan = org.plan

    plans_info = [
        {
            "id": "free",
            "name": "Developer",
            "badge": "Forever Free",
            "price": "$0",
            "period": "forever",
            "description": "Essential schema drift detection for solo developers and local databases.",
            "max_pipelines": 5,
            "highlight": False,
            "cta_text": "Current Plan" if current_plan == "free" and user_info else "Start Free ⚡",
            "features": [
                "Up to 5 monitored database pipelines",
                "Lazy extractors (Postgres, MySQL, SQLite)",
                "Daily automated schema audits",
                "Integrity-signed contract baselines",
                "Email drift alerts",
                "Single workspace seat"
            ],
            "unavailable": [
                "Snowflake, Databricks & Cloud connectors",
                "High-frequency minute cron schedules",
                "Slack & WhatsApp instant webhooks",
                "CI/CD Gate API Keys & Airflow Operator",
                "AI Root-Cause Diagnostics & SQL repair"
            ]
        },
        {
            "id": "pro",
            "name": "Team Pro",
            "badge": "Most Popular",
            "price": "$49 / ₹3,999",
            "period": "per month",
            "description": "Continuous schema governance, CI/CD gates, and instant alerts for high-growth data teams.",
            "max_pipelines": 50,
            "highlight": True,
            "cta_text": "Current Plan" if current_plan == "pro" else "Upgrade to Pro 🚀",
            "features": [
                "Up to 50 monitored database pipelines",
                "All databases (Postgres, MySQL, Snowflake, SQL Server, Databricks)",
                "High-frequency Cron audits (down to 1 min)",
                "Instant Slack & WhatsApp alert webhooks",
                "Unlimited CI/CD Gate API Keys",
                "Native Airflow Operator & Sensor export",
                "AI Root-Cause Diagnostics & SQL repair generator",
                "10 Team seats with Admin/Operator RBAC",
                "Email & community priority support"
            ],
            "unavailable": [
                "Custom on-prem contract SLAs",
                "Dedicated enterprise cluster connectors"
            ]
        },
        {
            "id": "enterprise",
            "name": "Enterprise",
            "badge": "Full Governance",
            "price": "$199 / ₹15,999",
            "period": "per month",
            "description": "Mission-critical schema contracts, immutable audit trails, and multi-tenant compliance.",
            "max_pipelines": 1000,
            "highlight": False,
            "cta_text": "Current Plan" if current_plan == "enterprise" else "Get Enterprise 👑",
            "features": [
                "Up to 1,000 monitored pipelines",
                "Dedicated Snowflake, Databricks & BigQuery cluster extractors",
                "Custom schema validation rules & column regex SLAs",
                "Unlimited team members & multi-organization switching",
                "Full immutable SOC2-ready audit trail export",
                "24/7 dedicated support & private Slack channel",
                "99.9% uptime SLA"
            ],
            "unavailable": []
        }
    ]

    return render(request, 'core/pricing.html', {
        'plans': plans_info,
        'current_plan': current_plan,
        'org': org,
        'user': user_info,
        'is_logged_in': bool(user_info),
        'payee_name': 'Anilbhai Isvarbhai Solanki',
        'upi_id': '9558322778@pthdfc',
        'qr_image_url': '/static/core/images/payment_upi_qr.jpg'
    })


# -------------------------------------------------------------
# Dynamic Shields.io Status Badge for Repositories & CI/CD
# -------------------------------------------------------------
def pipeline_badge_api(request, id):
    """
    Public dynamic SVG status badge for GitHub READMEs.
    Returns shields.io-compatible SVG: schema guard | passing (green), drifted (amber), failed (red).
    """
    from core.models import Pipeline
    from django.http import HttpResponse

    pipeline = Pipeline.objects.filter(id=id).first()
    if not pipeline:
        status_text = "unknown"
        status_color = "#64748b"
    elif pipeline.status == "Clean":
        status_text = "passing"
        status_color = "#10b981"
    elif pipeline.status == "Drifted":
        status_text = "drifted"
        status_color = "#f59e0b"
    elif pipeline.status == "Failed":
        status_text = "failed"
        status_color = "#ef4444"
    else:
        status_text = (pipeline.status or "active").lower()
        status_color = "#3b82f6"

    label = "schema guard"
    label_width = 86
    value_width = 16 + (len(status_text) * 7)
    total_width = label_width + value_width

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{label}: {status_text}">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#0f172a"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{status_color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="{label_width * 5}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">{label}</text>
    <text x="{label_width * 5}" y="140" transform="scale(.1)" fill="#fff">{label}</text>
    <text aria-hidden="true" x="{(label_width + value_width / 2) * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">{status_text}</text>
    <text x="{(label_width + value_width / 2) * 10}" y="140" transform="scale(.1)" fill="#fff">{status_text}</text>
  </g>
</svg>"""
    response = HttpResponse(svg, content_type="image/svg+xml")
    response["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


# -------------------------------------------------------------
# Audit Trail CSV Export API
# -------------------------------------------------------------
@require_login
def audit_logs_export_csv(request):
    """
    Export audit trail entries to CSV format for SOC2/ISO compliance reviews.
    """
    import csv
    from django.http import HttpResponse
    from core.models import AuditLog

    user_info = request.session.get('user', {})
    org_id = user_info.get('organization_id')
    role = user_info.get('role')

    if role == 'admin':
        logs = AuditLog.objects.all().order_by('-timestamp')[:5000]
    else:
        logs = AuditLog.objects.filter(organization_id=org_id).order_by('-timestamp')[:5000]

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="schema_guard_audit_trail.csv"'

    writer = csv.writer(response)
    writer.writerow(['ID', 'Timestamp (UTC)', 'Actor', 'Organization ID', 'Action', 'Target Type', 'Target ID', 'IP Address', 'Details'])

    for l in logs:
        writer.writerow([
            l.id,
            l.timestamp.strftime('%Y-%m-%d %H:%M:%S') if l.timestamp else '',
            l.actor,
            l.organization_id or '',
            l.action,
            l.target_type,
            l.target_id,
            l.ip_address or '',
            json.dumps(l.details) if l.details else ''
        ])

    return response


def build_user_session_dict(user_obj):
    """Helper to construct rich user session dictionary with profile details."""
    full_name = getattr(user_obj, 'full_name', '') or user_obj.username
    org_name = user_obj.organization.name if user_obj.organization else "Production Org"
    org_plan = (user_obj.organization.plan if user_obj.organization else "free") or "free"
    max_pipes = user_obj.organization.max_pipelines if user_obj.organization else 5
    return {
        "username": user_obj.username,
        "email": user_obj.email,
        "role": user_obj.role,
        "permissions": user_obj.permissions,
        "organization_id": user_obj.organization_id,
        "organization_name": org_name,
        "plan": org_plan,
        "max_pipelines": max_pipes,
        "is_verified": user_obj.is_verified,
        "full_name": full_name,
        "job_title": getattr(user_obj, 'job_title', ''),
        "bio": getattr(user_obj, 'bio', ''),
        "avatar_url": f"/api/user/avatar/{user_obj.username}"
    }


@csrf_exempt
@require_login
def user_profile_api(request):
    """GET/POST endpoint for viewing and updating user profile data and avatar."""
    import base64
    from core.models import User
    session_user = request.session.get('user', {})
    username = session_user.get('username')
    user_obj = User.objects.filter(username=username).first()
    if not user_obj:
        return JsonResponse({"error": "User account not found"}, status=404)
        
    if request.method == "GET":
        return JsonResponse({
            "success": True,
            "user": {
                "username": user_obj.username,
                "email": user_obj.email,
                "full_name": user_obj.full_name or user_obj.username,
                "job_title": user_obj.job_title,
                "bio": user_obj.bio,
                "role": user_obj.role,
                "organization_name": user_obj.organization.name if user_obj.organization else "Production Org",
                "avatar_url": f"/api/user/avatar/{user_obj.username}",
                "has_custom_avatar": bool(user_obj.avatar_data)
            }
        })
        
    elif request.method == "POST":
        try:
            if request.content_type == 'application/json':
                data = json.loads(request.body.decode('utf-8'))
            else:
                data = request.POST.dict()
        except Exception:
            data = {}

        # 1. Update Full Name
        if 'full_name' in data:
            user_obj.full_name = data['full_name'].strip()
            
        # 2. Update Job Title & Bio
        if 'job_title' in data:
            user_obj.job_title = data['job_title'].strip()
        if 'bio' in data:
            user_obj.bio = data['bio'].strip()
            
        # 3. Update Email (if unique)
        new_email = data.get('email', '').strip()
        if new_email and new_email != user_obj.email:
            existing = User.objects.filter(email=new_email).exclude(username=user_obj.username).first()
            if existing:
                return JsonResponse({"error": "This email address is already in use by another account."}, status=400)
            user_obj.email = new_email

        # 4. Update Avatar (file or base64)
        if 'avatar_data' in data:
            user_obj.avatar_data = data['avatar_data']
        elif 'avatar_file' in request.FILES:
            avatar_file = request.FILES['avatar_file']
            if avatar_file.size > 5 * 1024 * 1024:
                return JsonResponse({"error": "Image file too large (max 5MB)"}, status=400)
            encoded = base64.b64encode(avatar_file.read()).decode('utf-8')
            mime = avatar_file.content_type or 'image/png'
            user_obj.avatar_data = f"data:{mime};base64,{encoded}"

        # 5. Optional Password Change
        new_pw = data.get('new_password')
        current_pw = data.get('current_password')
        if new_pw:
            if not current_pw or not verify_password(current_pw, user_obj.password_hash):
                return JsonResponse({"error": "Current password is required and was incorrect."}, status=400)
            if len(new_pw) < 6:
                return JsonResponse({"error": "New password must be at least 6 characters."}, status=400)
            user_obj.password_hash = hash_password(new_pw)

        user_obj.save()
        
        # Update session
        request.session['user'] = build_user_session_dict(user_obj)
        log_action(request, 'user.profile_update', 'user', user_obj.username)
        
        return JsonResponse({
            "success": True,
            "message": "Profile updated successfully!",
            "user": {
                "username": user_obj.username,
                "email": user_obj.email,
                "full_name": user_obj.full_name or user_obj.username,
                "job_title": user_obj.job_title,
                "bio": user_obj.bio,
                "avatar_url": f"/api/user/avatar/{user_obj.username}",
                "has_custom_avatar": bool(user_obj.avatar_data)
            }
        })

    return JsonResponse({"error": "Method not allowed"}, status=405)


def user_avatar_api(request, username):
    """Dynamic avatar serving endpoint with custom photo base64 decoding and SVG initials fallback."""
    import base64
    from core.models import User
    
    # If explicit reset requested, skip custom avatar
    skip_custom = request.GET.get('reset') == '1'
    user = User.objects.filter(username=username).first()
    
    if user and user.avatar_data and not skip_custom:
        avatar = user.avatar_data.strip()
        if avatar.startswith('data:image/'):
            try:
                header, encoded = avatar.split(',', 1)
                mime_type = header.split(';')[0].replace('data:', '')
                image_data = base64.b64decode(encoded)
                response = HttpResponse(image_data, content_type=mime_type)
                response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                return response
            except Exception as e:
                logger.warning(f"Failed to decode base64 avatar for {username}: {e}")
        elif avatar.startswith('http://') or avatar.startswith('https://'):
            return redirect(avatar)
            
    # Fallback: Dynamic SVG avatar with user's initials
    initials = ""
    if user and user.full_name:
        parts = user.full_name.strip().split()
        initials = "".join([p[0].upper() for p in parts[:2]])
    elif username:
        initials = username[:2].upper()
    else:
        initials = "SG"
        
    svg = f"""<svg width="64" height="64" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="avGrad" x1="0" y1="0" x2="64" y2="64" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#38bdf8"/>
      <stop offset="50%" stop-color="#6366f1"/>
      <stop offset="100%" stop-color="#a855f7"/>
    </linearGradient>
  </defs>
  <rect width="64" height="64" rx="32" fill="url(#avGrad)"/>
  <text x="32" y="39" text-anchor="middle" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="22" font-weight="700" fill="#ffffff" letter-spacing="0.5">{initials}</text>
</svg>"""
    response = HttpResponse(svg, content_type="image/svg+xml")
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response





