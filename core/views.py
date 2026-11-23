import os
import re
import json
import logging
import random
import functools
import uuid
from datetime import datetime, timezone, timedelta
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse, HttpResponseNotAllowed
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
from core.db_connector import create_db_engine
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

    if db_type:
        from core.db_connector import normalize_connection_url
        return normalize_connection_url(db_type, decrypted)
    return decrypted

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
            
    # Rehydrate snapshot from DB if missing on disk or if hash needs validation
    from core.models import SchemaSnapshot
    from schema_guard.snapshot import _compute_hash
    latest_snap = SchemaSnapshot.objects.filter(pipeline=pipeline_obj).order_by('-version').first()
    if latest_snap and latest_snap.schema_data:
        snap_hash = _compute_hash(latest_snap.schema_data)
        snap_payload = {
            "captured_at": latest_snap.captured_at.isoformat(),
            "hash": snap_hash,
            "schema": latest_snap.schema_data
        }
        with open(snapshot_path, "w", encoding="utf-8") as f:
            json.dump(snap_payload, f, indent=2)
    elif not os.path.exists(snapshot_path):
        legacy_snap = os.path.join(SNAPSHOTS_DIR, f"{pipeline_obj.table}.json")
        if os.path.exists(legacy_snap):
            snapshot_path = legacy_snap
            
    return contract_path, snapshot_path

def perform_data_quality_validation(db_type, conn_str, schema_name, table_name, schema_columns):
    from sqlalchemy import text
    
    resolved_conn = resolve_connection_string(conn_str, db_type)
    engine, _ = create_db_engine(db_type, resolved_conn, timeout=10)
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
            raw_rows = conn.execute(row_count_q).scalar()
            try:
                total_rows = int(raw_rows) if raw_rows is not None else 0
            except (TypeError, ValueError):
                total_rows = 0
            
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
                    raw_null = conn.execute(null_q).scalar()
                    try:
                        null_count = int(raw_null) if raw_null is not None else 0
                    except (TypeError, ValueError):
                        null_count = 0
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
                    raw_dup = conn.execute(dup_q).scalar()
                    try:
                        dup_count = int(raw_dup) if raw_dup is not None else 0
                    except (TypeError, ValueError):
                        dup_count = 0
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

            # 4. Column Allowed Values / Enum Assertion
            enum_cols = [c for c in schema_columns if c.get("allowed_values") or c.get("enum")]
            if enum_cols and total_rows > 0:
                enum_failures = []
                for col in enum_cols:
                    col_name = col["name"]
                    vals = col.get("allowed_values") or col.get("enum") or []
                    if vals:
                        safe_col = sanitize_sql_identifier(col_name, db_type)
                        escaped_vals = ", ".join([f"'{str(v).replace("'", "''")}'" for v in vals])
                        enum_q = text(f"SELECT COUNT(*) FROM {target_table} WHERE {safe_col} IS NOT NULL AND {safe_col} NOT IN ({escaped_vals})")
                        raw_invalid = conn.execute(enum_q).scalar()
                        try:
                            invalid_count = int(raw_invalid) if raw_invalid is not None else 0
                        except (TypeError, ValueError):
                            invalid_count = 0
                        if invalid_count > 0:
                            enum_failures.append(f"{col_name}: {invalid_count} out-of-domain value(s)")

                checks.append({
                    "name": "Enum Domain Compliance",
                    "description": "Verifies that column values adhere to allowed enum domain values",
                    "metric": ", ".join(enum_failures) if enum_failures else "All domain constraints satisfied.",
                    "status": "FAIL" if enum_failures else "PASS"
                })
                if enum_failures:
                    status = "FAIL"

            # 5. Range Constraints (Min / Max)
            range_cols = [c for c in schema_columns if c.get("min_value") is not None or c.get("max_value") is not None]
            if range_cols and total_rows > 0:
                range_failures = []
                for col in range_cols:
                    col_name = col["name"]
                    safe_col = sanitize_sql_identifier(col_name, db_type)
                    conditions = []
                    if col.get("min_value") is not None:
                        conditions.append(f"{safe_col} < {col['min_value']}")
                    if col.get("max_value") is not None:
                        conditions.append(f"{safe_col} > {col['max_value']}")
                    if conditions:
                        cond_str = " OR ".join(conditions)
                        range_q = text(f"SELECT COUNT(*) FROM {target_table} WHERE {safe_col} IS NOT NULL AND ({cond_str})")
                        raw_oob = conn.execute(range_q).scalar()
                        try:
                            out_of_bounds = int(raw_oob) if raw_oob is not None else 0
                        except (TypeError, ValueError):
                            out_of_bounds = 0
                        if out_of_bounds > 0:
                            range_failures.append(f"{col_name}: {out_of_bounds} record(s) out of bounds")

                checks.append({
                    "name": "Range Bound Compliance",
                    "description": "Verifies numerical / date column values respect minimum and maximum bounds",
                    "metric": ", ".join(range_failures) if range_failures else "All range constraints satisfied.",
                    "status": "FAIL" if range_failures else "PASS"
                })
                if range_failures:
                    status = "FAIL"
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

def send_custom_webhook_alert(violations, dq_report, webhook_url, pipeline_name, status_str, pipeline_id=None, secret=None) -> bool:
    from datetime import datetime, timezone
    from core.notifications import dispatch_signed_webhook
    from django.conf import settings

    payload = {
        "event": "schema_guard.drift_detected" if violations else "schema_guard.data_quality_failure",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pipeline": pipeline_name,
        "pipeline_id": pipeline_id,
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

    pipeline_obj = None
    if pipeline_id:
        try:
            from core.models import Pipeline
            pipeline_obj = Pipeline.objects.filter(id=pipeline_id).first()
        except Exception:
            pass

    allow_internal = getattr(settings, 'IS_TESTING', False)
    ok, reason, meta = dispatch_signed_webhook(
        url=webhook_url,
        payload=payload,
        secret=secret,
        event=payload["event"],
        pipeline=pipeline_obj,
        max_retries=1,
        webhook_type="custom",
        allow_internal=allow_internal
    )
    return ok

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


def send_invitation_email(email: str, org_name: str, invited_by: str, role: str, invite_url: str) -> bool:
    subject = f"You've been invited to join {org_name} on Schema Guard"
    message = (
        f"Hello,\n\n"
        f"{invited_by} has invited you to join the '{org_name}' workspace on Schema Guard as an {role.title()}.\n\n"
        f"Accept your invitation here:\n{invite_url}\n\n"
        f"This invitation link will expire in 7 days.\n\n"
        f"— Schema Guard Team"
    )
    role_bg = "#8b5cf6" if role == 'subadmin' else ("#0ea5e9" if role == 'operator' else "#10b981")
    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Join {org_name} on Schema Guard</title>
    </head>
    <body style="font-family: 'Outfit', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #030712; color: #f3f4f6; margin: 0; padding: 40px 20px;">
        <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 580px; background: linear-gradient(135deg, #0b0f19 0%, #111827 100%); border: 1px solid rgba(139, 92, 246, 0.25); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(0,0,0,0.7); border-collapse: collapse;">
            <tr>
                <td height="4" style="background: linear-gradient(90deg, #8b5cf6, #38bdf8, #22c55e);"></td>
            </tr>
            <tr>
                <td style="padding: 40px 40px 20px 40px; text-align: center;">
                    <div style="display: inline-block; background: rgba(139, 92, 246, 0.08); border: 1.5px solid rgba(139, 92, 246, 0.3); border-radius: 12px; padding: 12px 20px; text-align: center; margin-bottom: 25px;">
                        <span style="font-size: 24px; vertical-align: middle;">🛡️</span>
                        <span style="font-size: 18px; font-weight: 800; color: #ffffff; letter-spacing: 1px; vertical-align: middle; margin-left: 8px;">Schema <span style="color: #a78bfa;">Guard</span></span>
                    </div>
                    <h1 style="color: #ffffff; font-size: 24px; font-weight: 800; margin: 0; letter-spacing: -0.02em;">Team Workspace Invitation</h1>
                </td>
            </tr>
            <tr>
                <td style="padding: 0 40px 30px 40px;">
                    <p style="color: #94a3b8; font-size: 15px; line-height: 1.6; margin: 0 0 20px 0;">
                        <strong style="color: #ffffff;">{invited_by}</strong> has invited you to join and collaborate in the <strong style="color: #38bdf8;">{org_name}</strong> workspace on Schema Guard.
                    </p>
                    <div style="background: #0f172a; border-radius: 10px; padding: 16px 20px; margin-bottom: 25px; border: 1px solid rgba(255,255,255,0.06);">
                        <div style="margin-bottom: 8px;">
                            <span style="color: #64748b; font-size: 12px; text-transform: uppercase; font-weight: 700;">Workspace Role: </span>
                            <span style="background: {role_bg}; color: #ffffff; font-size: 11px; font-weight: 800; padding: 3px 8px; border-radius: 4px; text-transform: uppercase;">{role.upper()}</span>
                        </div>
                        <div style="color: #94a3b8; font-size: 13px; line-height: 1.5;">
                            Collaborate on data contracts, shadow-simulate SQL DDL migrations, and monitor automated schema drift checks.
                        </div>
                    </div>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{invite_url}" style="display: inline-block; background: linear-gradient(135deg, #8b5cf6, #6366f1); color: #ffffff; text-decoration: none; font-weight: 700; font-size: 15px; padding: 14px 32px; border-radius: 8px; box-shadow: 0 4px 15px rgba(139, 92, 246, 0.4);">Accept Invitation & Join Workspace →</a>
                    </div>
                    <p style="color: #64748b; font-size: 12px; line-height: 1.5; margin: 20px 0 0 0; text-align: center;">
                        This invitation link is valid for 7 days.<br>
                        If the button above does not work, copy and paste this URL into your browser:<br>
                        <a href="{invite_url}" style="color: #8b5cf6; word-break: break-all;">{invite_url}</a>
                    </p>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    print(f"\n========================================\n[EMAIL] Workspace invitation to {email} for {org_name}: {invite_url}\n========================================\n")
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
            from core.db_connector import get_db_columns
            resolved_conn = resolve_connection_string(p["connStr"], p.get("dbType"))
            live_schema = get_db_columns(p["dbType"], resolved_conn, p.get("schema"), p["table"])
            
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
        try:
            snapshot = load_snapshot(snapshot_path)
        except ValueError as snap_err:
            logs.append(f"[WARNING] Snapshot verification issue: {snap_err}. Resynchronizing snapshot hash...")
            with open(snapshot_path, "r", encoding="utf-8") as f:
                snap_raw = json.load(f)
            from schema_guard.snapshot import capture_snapshot
            snapshot = capture_snapshot(snap_raw.get("schema", {}), snapshot_path)

        logs.append("[INFO] Fetching schema catalog lists from database...")
        from core.db_connector import get_db_columns
        resolved_conn = resolve_connection_string(p["connStr"], p.get("dbType"))
        live_schema = get_db_columns(p["dbType"], resolved_conn, p.get("schema"), p["table"])
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

            from core.notifications import calculate_drift_severity, evaluate_alert_routing
            drift_severity = calculate_drift_severity(violations, dq_report.get("status", "PASS"))
            env_val = p.get("environment", "prod")
            routed = evaluate_alert_routing(p.get("alerts", {}), drift_severity, environment=env_val)

            dispatched_channels = set()
            for r in routed:
                ch = r["channel"]
                target = r["target"]
                if ch == "email":
                    if send_email_alert(desc_warnings, email_to=target):
                        alert_sent = True
                        dispatched_channels.add("email")
                        logs.append(f"[INFO] Routed email alert dispatched to {target} (Severity: {drift_severity}).")
                elif ch == "slack":
                    from core.notifications import send_rich_slack_alert
                    ok, reason = send_rich_slack_alert(desc_warnings, pipeline_name=p["name"], table_name=p.get("table"), db_type=p.get("dbType", "database"), webhook_url=target)
                    if ok:
                        alert_sent = True
                        dispatched_channels.add("slack")
                        logs.append(f"[INFO] Routed Slack Block Kit alert dispatched (Severity: {drift_severity}).")
                    else:
                        logs.append(f"[WARN] Slack alert failed: {reason}")
                elif ch == "teams":
                    from core.notifications import send_rich_teams_alert
                    ok, reason = send_rich_teams_alert(desc_warnings, pipeline_name=p["name"], table_name=p.get("table"), db_type=p.get("dbType", "database"), webhook_url=target)
                    if ok:
                        alert_sent = True
                        dispatched_channels.add("teams")
                        logs.append(f"[INFO] Routed Microsoft Teams alert card dispatched (Severity: {drift_severity}).")
                    else:
                        logs.append(f"[WARN] Teams alert failed: {reason}")
                elif ch == "wp":
                    if send_whatsapp_alert(desc_warnings, phone=target):
                        alert_sent = True
                        dispatched_channels.add("whatsapp")
                        logs.append(f"[INFO] Routed WhatsApp alert dispatched to {target}.")
                elif ch == "webhook":
                    if send_custom_webhook_alert(
                        violations,
                        dq_report,
                        target,
                        p["name"],
                        status_str,
                        pipeline_id=p.get("id"),
                        secret=p["alerts"].get("webhook_secret")
                    ):
                        alert_sent = True
                        dispatched_channels.add("webhook")
                        logs.append(f"[INFO] Routed Custom Webhook payload dispatched to {target}.")
                    else:
                        logs.append("[ERROR] Custom Webhook dispatch failed.")

            if not alert_sent and not p["alerts"].get("routing", {}).get("enabled"):
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
                from schema_guard.snapshot import _compute_hash
                SchemaSnapshot.objects.create(
                    pipeline=p_obj_snap,
                    version=last_ver + 1,
                    schema_data=live_schema,
                    hash=_compute_hash(live_schema),
                    status=status_str,
                    violations_count=len(violations),
                    captured_by='system_check'
                )
        except Exception as snap_save_err:
            logger.warning(f"Could not record SchemaSnapshot history: {snap_save_err}")

        # Synchronize Drift Incident Lifecycle
        try:
            from core.models import DriftIncident, AuditLog
            p_obj_inc = Pipeline.objects.filter(id=pipeline_id).first()
            if p_obj_inc:
                now_dt = datetime.now(timezone.utc)
                if status_str == "Drifted" and violations:
                    active_inc = DriftIncident.objects.filter(
                        pipeline=p_obj_inc,
                        status__in=['OPEN', 'ACKNOWLEDGED']
                    ).first()

                    v_upper = " ".join(str(v).upper() for v in violations)
                    if any(kw in v_upper for kw in ["DROPPED", "MISSING", "NOT FOUND", "BREAKING", "TYPE"]):
                        sev = "CRITICAL"
                    elif any(kw in v_upper for kw in ["NULL", "PRIMARY", "UNIQUE"]):
                        sev = "HIGH"
                    else:
                        sev = "MEDIUM"

                    if not active_inc:
                        inc_num = f"INC-{now_dt.year}-{uuid.uuid4().hex[:6].upper()}"
                        DriftIncident.objects.create(
                            incident_number=inc_num,
                            pipeline=p_obj_inc,
                            status='OPEN',
                            severity=sev,
                            title=f"Schema Drift: {len(violations)} contract violation(s) on {p_obj_inc.name}",
                            violations=list(violations),
                            violations_count=len(violations),
                        )
                        AuditLog.objects.create(
                            action='incident.create',
                            actor='system_check',
                            target_type='drift_incident',
                            target_id=inc_num,
                            organization=p_obj_inc.organization,
                            details={
                                "pipeline_id": p_obj_inc.id,
                                "pipeline_name": p_obj_inc.name,
                                "severity": sev,
                                "violations_count": len(violations)
                            }
                        )
                    else:
                        active_inc.violations = list(violations)
                        active_inc.violations_count = len(violations)
                        active_inc.severity = sev
                        active_inc.save()
                elif status_str == "Clean":
                    active_incidents = DriftIncident.objects.filter(
                        pipeline=p_obj_inc,
                        status__in=['OPEN', 'ACKNOWLEDGED', 'SNOOZED']
                    )
                    for inc in active_incidents:
                        inc.status = 'RESOLVED'
                        inc.auto_resolved = True
                        inc.resolved_by = 'system (auto-verified)'
                        inc.resolved_at = now_dt
                        inc.resolution_notes = 'Automatically resolved: Database schema verified in full alignment with locked contract baseline.'
                        inc.mttr_seconds = int((now_dt - inc.created_at).total_seconds()) if inc.created_at else 0
                        inc.save()
                        AuditLog.objects.create(
                            action='incident.resolve',
                            actor='system_check',
                            target_type='drift_incident',
                            target_id=inc.incident_number,
                            organization=p_obj_inc.organization,
                            details={
                                "pipeline_id": p_obj_inc.id,
                                "pipeline_name": p_obj_inc.name,
                                "auto_resolved": True,
                                "mttr_seconds": inc.mttr_seconds
                            }
                        )
        except Exception as inc_err:
            logger.warning(f"Could not synchronize DriftIncident: {inc_err}")

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
    
    # Sync session user if organization or plan updated
    if user and user.organization:
        request.session['user'] = build_user_session_dict(user)
        
    raw_plan = (org.plan if org and org.plan else 'free').lower().strip()
    clean_plan = raw_plan if raw_plan in ('free', 'pro', 'enterprise') else 'free'
    return render(request, 'core/dashboard.html', {
        'org': org,
        'plan': clean_plan,
        'max_pipelines': org.max_pipelines if org else 5
    })

@require_login
def builder_page(request):
    # Require see / edit permissions
    user_info = request.session.get('user', {})
    if not user_info.get('permissions', {}).get('see', True) and user_info.get('role') not in ['admin', 'subadmin']:
        return HttpResponse("Unauthorized to view yaml builder.", status=403)

    from core.models import User, Pipeline
    user = User.objects.filter(username=user_info.get('username')).first()
    pipelines = []
    if user and user.organization:
        pipelines = list(Pipeline.objects.filter(organization=user.organization).values('id', 'name', 'db_type', 'schema', 'table'))
    elif user:
        pipelines = list(Pipeline.objects.all().values('id', 'name', 'db_type', 'schema', 'table')[:25])

    return render(request, 'core/builder.html', {'pipelines': pipelines})

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
    if user_info.get('role') != 'admin':
        from core.models import User, Organization, Pipeline
        user_obj = User.objects.filter(username=user_info.get('username')).first()
        org = user_obj.organization if user_obj and user_obj.organization else None
        if not org and user_info.get('organization_id'):
            org = Organization.objects.filter(id=user_info.get('organization_id')).first()
            
        if user_obj and org:
            request.session['user'] = build_user_session_dict(user_obj)

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
        "environment": (data.get("environment") or "prod").strip().lower(),
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
    from schema_guard.snapshot import _compute_hash
    try:
        SchemaSnapshot.objects.create(
            pipeline_id=pipe_id,
            version=1,
            schema_data=live_schema,
            hash=_compute_hash(live_schema),
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
def create_demo_pipeline_api(request):
    """
    1-click onboarding endpoint that creates a realistic sample PostgreSQL pipeline
    with pre-loaded baseline contract, data quality checks, and drift mismatch.
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    import secrets
    from datetime import timedelta
    user_info = request.session.get('user', {})
    from core.models import User, Organization
    user_obj = User.objects.filter(username=user_info.get('username')).first()
    org = user_obj.organization if user_obj and user_obj.organization else None
    if not org and user_info.get('organization_id'):
        org = Organization.objects.filter(id=user_info.get('organization_id')).first()

    pipe_id = f"demo_orders_{secrets.token_hex(3)}"
    now_dt = datetime.now(timezone.utc)
    now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")

    contract_yaml_sample = """version: 1
source:
  name: demo_orders_contract
  type: postgres
  schema: public
  table: orders
columns:
  - name: id
    type: integer
    nullable: false
    primary_key: true
  - name: customer_id
    type: integer
    nullable: false
  - name: total_amount
    type: numeric(12,2)
    nullable: false
  - name: status
    type: varchar(50)
    nullable: false
  - name: created_at
    type: timestamp
    nullable: false
"""

    schema_map_sample = {
        "left": [
            {"name": "id", "type": "integer", "pk": True, "nullable": False, "status": "clean"},
            {"name": "customer_id", "type": "integer", "pk": False, "nullable": False, "status": "clean"},
            {"name": "total_amount", "type": "numeric(12,2)", "pk": False, "nullable": False, "status": "changed"},
            {"name": "status", "type": "varchar(50)", "pk": False, "nullable": False, "status": "changed"},
            {"name": "created_at", "type": "timestamp", "pk": False, "nullable": False, "status": "removed"}
        ],
        "right": [
            {"name": "id", "type": "integer", "pk": True, "nullable": False, "status": "clean"},
            {"name": "customer_id", "type": "integer", "pk": False, "nullable": False, "status": "clean"},
            {"name": "total_amount", "type": "varchar(100)", "pk": False, "nullable": False, "status": "changed"},
            {"name": "status", "type": "varchar(50)", "pk": False, "nullable": True, "status": "changed"},
            {"name": "shipping_address", "type": "text", "pk": False, "nullable": True, "status": "added"}
        ],
        "dataQuality": {
            "status": "FAIL",
            "checks": [
                {"name": "Primary Key Integrity", "description": "Ensures ID column contains unique non-null integers", "metric": "0 nulls, 100% unique", "status": "PASS"},
                {"name": "Financial Precision Check", "description": "Ensures total_amount maintains numeric(12,2) scale", "metric": "Failed: non-numeric string values found in total_amount", "status": "FAIL"},
                {"name": "Order Status Enum", "description": "Validates status against pending/completed/cancelled", "metric": "3 null records violate contract", "status": "FAIL"}
            ]
        }
    }

    logs_sample = [
        "[INFO] Establishing connection to target database...",
        "[INFO] Target: public.orders (PostgreSQL 16 Engine)",
        "[INFO] Verifying contract signature lock integrity: PASSED.",
        "[INFO] Extracting live schema catalog from target instance...",
        "[INFO] Running data quality metric validations...",
        "[ERROR] Data Quality - Financial Precision Check: Failed: non-numeric string values found in total_amount",
        "[ERROR] Data Quality - Order Status Enum: 3 null records violate contract",
        "[INFO] Running schema diff gate comparison checks against cryptographic baseline...",
        "[WARNING] COMPLIANCE VIOLATION DETECTED:",
        "[ERROR] Column 'created_at' was dropped from live database table 'orders'.",
        "[ERROR] Column 'total_amount': type changed from numeric(12,2) to varchar(100).",
        "[ERROR] Column 'status': nullable changed from NOT NULL to NULL.",
        "[INFO] New unannounced column 'shipping_address' detected in live schema.",
        "[ERROR] Verification FAILED: 3 structural drift violations detected."
    ]

    compliance_history_sample = [
        {"time": now_str, "profile": "production", "status": "FAIL", "violations": 4, "alertEvent": "Email"},
        {"time": (now_dt - timedelta(hours=6)).strftime("%Y-%m-%d %H:%M:%S"), "profile": "production", "status": "PASS", "violations": 0, "alertEvent": "None"}
    ]

    p_dict = {
        "id": pipe_id,
        "name": "Demo E-Commerce Orders",
        "dbType": "postgres",
        "connStr": "postgresql://demo_user:demo_secret@postgres.demo.schemaguard.internal:5432/ecommerce",
        "schema": "public",
        "table": "orders",
        "cron": "0 0 * * *",
        "cronText": "Daily preset",
        "alerts": {"email": user_info.get("email", "demo@schemaguard.com")},
        "status": "Drifted",
        "lastChecked": now_str,
        "lockSignature": f"sha256_demo_{secrets.token_hex(8)}",
        "schemaMap": schema_map_sample,
        "contractYaml": contract_yaml_sample,
        "logs": logs_sample,
        "complianceHistory": compliance_history_sample,
        "organization_id": org.id if org else None
    }

    new_pipe = db.create_pipeline(p_dict)
    log_action(request, 'pipeline.create_demo', 'pipeline', pipe_id)
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
    if "environment" in data and data.get("environment"):
        updates["environment"] = data.get("environment").strip().lower()
    
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
def promote_pipeline_api(request, id):
    """
    Multi-Environment Promotion API (Dev -> Staging -> Prod).
    Promotes a verified schema contract and its lock signature from a lower environment
    to a higher environment (e.g. dev -> staging, or staging -> prod).
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    if user_info.get('role') not in ['admin', 'subadmin', 'operator']:
        return JsonResponse({
            "detail": "Permission denied: Promoting contracts across environments requires Admin, Subadmin, or Operator role."
        }, status=403)

    from core.models import Pipeline, User
    from core.db_impl import serialize_pipeline

    source_p = Pipeline.objects.filter(id=id).first()
    if not source_p:
        return JsonResponse({"detail": "Source pipeline not found."}, status=404)

    # Enforce organization boundary
    if user_info.get('role') != 'admin' and source_p.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    try:
        data = json.loads(request.body) if request.body else {}
    except Exception:
        data = {}

    source_env = (source_p.environment or "prod").lower()
    target_env = (data.get("target_environment") or data.get("target_env") or "").strip().lower()

    if not target_env:
        # Auto-compute next environment in progression: dev -> staging -> prod
        if source_env == 'dev':
            target_env = 'staging'
        elif source_env == 'staging':
            target_env = 'prod'
        else:
            return JsonResponse({"detail": "Pipeline is already in Production (highest environment)."}, status=400)

    valid_targets = ['staging', 'prod'] if source_env == 'dev' else ['prod'] if source_env == 'staging' else []
    if target_env not in valid_targets:
        return JsonResponse({
            "detail": f"Cannot promote pipeline from '{source_env.upper()}' to '{target_env.upper()}'. Valid target environments: {', '.join(valid_targets).upper()}"
        }, status=400)

    target_pipeline_id = data.get("target_pipeline_id")
    target_p = None
    if target_pipeline_id:
        target_p = Pipeline.objects.filter(id=target_pipeline_id).first()
        if not target_p:
            return JsonResponse({"detail": f"Target pipeline '{target_pipeline_id}' not found."}, status=404)
        if user_info.get('role') != 'admin' and target_p.organization_id != user_info.get('organization_id'):
            return JsonResponse({"detail": "Unauthorized target pipeline access."}, status=403)

    # Contract to promote
    contract_yaml = source_p.contract_yaml
    lock_signature = source_p.lock_signature
    schema_map = source_p.schema_map

    if not contract_yaml:
        return JsonResponse({
            "detail": "Cannot promote: Source pipeline does not have a defined YAML contract. Please build or reverse-engineer a contract first."
        }, status=400)

    if target_p:
        # Update existing target pipeline with promoted contract & signature
        target_p.contract_yaml = contract_yaml
        target_p.lock_signature = lock_signature
        target_p.schema_map = schema_map
        target_p.status = 'Clean'
        target_p.environment = target_env
        target_p.save(update_fields=['contract_yaml', 'lock_signature', 'schema_map', 'status', 'environment'])
        action_msg = f"Promoted and synchronized contract to existing {target_env.upper()} pipeline '{target_p.name}'"
        record_contract_version(target_p, user_info.get('username', 'system'), f"Promoted and synchronized from {source_env.upper()}")
    else:
        # Clone / Create a new pipeline in target environment
        import uuid
        target_name = (data.get("target_name") or f"{source_p.name} [{target_env.upper()}]").strip()
        new_pipe_id = f"pipe-{uuid.uuid4().hex[:12]}"
        target_conn = data.get("target_conn_str") or source_p.conn_str

        target_p = Pipeline.objects.create(
            id=new_pipe_id,
            name=target_name,
            environment=target_env,
            db_type=source_p.db_type,
            conn_str=target_conn,
            schema=source_p.schema,
            table=source_p.table,
            cron=source_p.cron,
            cron_text=source_p.cron_text,
            alerts=source_p.alerts,
            status='Clean',
            lock_signature=lock_signature,
            schema_map=schema_map,
            contract_yaml=contract_yaml,
            organization=source_p.organization
        )
        action_msg = f"Created new {target_env.upper()} pipeline '{target_p.name}' with promoted contract"
        record_contract_version(target_p, user_info.get('username', 'system'), f"Created in {target_env.upper()} via promotion from {source_env.upper()}")

    log_action(
        request,
        'pipeline.promoted',
        'pipeline',
        str(source_p.id),
        {
            'source_environment': source_env,
            'target_environment': target_env,
            'target_pipeline_id': target_p.id,
            'target_pipeline_name': target_p.name,
            'signature': lock_signature
        }
    )

    return JsonResponse({
        "success": True,
        "message": f"🚀 Successfully promoted schema contract from {source_env.upper()} to {target_env.upper()}! {action_msg}.",
        "source_environment": source_env,
        "target_environment": target_env,
        "mode": "sync" if target_pipeline_id else "new",
        "pipeline": serialize_pipeline(target_p),
        "promoted_pipeline": serialize_pipeline(target_p)
    })


@require_login
def test_pipeline_alert_api(request):
    """
    Tests sending a formatted alert payload (Slack, Teams, Custom Webhook, or Email)
    without running a full pipeline scan.
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body)
    except Exception:
        return JsonResponse({"detail": "Invalid JSON body"}, status=400)

    channel = (data.get("channel") or "slack").strip().lower()
    target = (data.get("target") or "").strip()
    pipeline_name = (data.get("pipeline_name") or "Sample Pipeline").strip()
    table_name = (data.get("table_name") or "orders").strip()
    db_type = (data.get("db_type") or "postgres").strip()

    if not target:
        return JsonResponse({"detail": f"Target URL or destination for {channel} cannot be empty."}, status=400)

    from core.notifications import send_rich_slack_alert, send_rich_teams_alert, validate_webhook_url

    test_violations = [
        f"Column 'user_id' DROPPED from contract schema for table '{table_name}'",
        "Column 'total_amount' TYPE MISMATCH (expected: bigint, found: numeric(14,2))",
        "Column 'status' NULL MISMATCH (expected: NOT NULL, found: nullable)"
    ]

    app_url = request.build_absolute_uri('/')[:-1]

    if channel == "slack":
        success, message = send_rich_slack_alert(
            test_violations,
            pipeline_name=pipeline_name,
            table_name=table_name,
            db_type=db_type,
            webhook_url=target,
            app_url=app_url,
            is_test=True
        )
    elif channel == "teams":
        success, message = send_rich_teams_alert(
            test_violations,
            pipeline_name=pipeline_name,
            table_name=table_name,
            db_type=db_type,
            webhook_url=target,
            app_url=app_url,
            is_test=True
        )
    elif channel == "webhook":
        is_valid, reason = validate_webhook_url(target)
        if not is_valid:
            return JsonResponse({"detail": reason}, status=400)
        success = send_custom_webhook_alert(
            test_violations,
            {"status": "FAIL", "checks": [{"name": "row_count", "description": "Row count check", "metric": "0", "status": "FAIL"}]},
            target,
            pipeline_name,
            "TEST_DRIFTED"
        )
        message = "Custom webhook dispatched successfully." if success else "Webhook destination rejected or unreachable."
    elif channel == "email":
        success = send_email_alert(test_violations, email_to=target)
        message = f"Test email dispatched to {target}" if success else "Failed to send test email."
    else:
        return JsonResponse({"detail": f"Unsupported channel '{channel}'."}, status=400)

    if success:
        return JsonResponse({"success": True, "message": message})
    return JsonResponse({"success": False, "detail": message}, status=400)


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
def run_scheduled_sweep_api(request):
    """Triggers an on-demand evaluation sweep of all scheduled pipelines."""
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    if user_info.get('role') not in ['admin', 'subadmin', 'operator']:
        return JsonResponse({"detail": "Permission denied"}, status=403)

    from core.management.commands.run_scheduled_checks import execute_pipeline_sweep
    try:
        data = json.loads(request.body) if request.body else {}
    except Exception:
        data = {}

    force = bool(data.get("force", False))
    pipeline_filter = data.get("pipeline_id")
    stats = execute_pipeline_sweep(pipeline_id_filter=pipeline_filter, force=force)
    return JsonResponse({"success": True, "stats": stats})


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
def run_scheduled_sweep_api(request):
    """Triggers an on-demand evaluation sweep of all scheduled pipelines."""
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    if user_info.get('role') not in ['admin', 'subadmin', 'operator']:
        return JsonResponse({"detail": "Permission denied"}, status=403)

    from core.management.commands.run_scheduled_checks import execute_pipeline_sweep
    try:
        data = json.loads(request.body) if request.body else {}
    except Exception:
        data = {}

    force = bool(data.get("force", False))
    pipeline_filter = data.get("pipeline_id")
    stats = execute_pipeline_sweep(pipeline_id_filter=pipeline_filter, force=force)
    return JsonResponse({"success": True, "stats": stats})

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


@require_login
def reverse_engineer_contract_api(request):
    """
    1-Click Live Schema Contract Generator.
    Inspects live database metadata (columns, data types, primary keys, nullability)
    and reverse-engineers a complete, locked Schema Guard YAML Contract, Pydantic model,
    TypeScript interface, and SQL DDL.
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body) if request.body else {}
    except Exception:
        return JsonResponse({"detail": "Invalid JSON body"}, status=400)

    from core.models import Pipeline, ConnectionProfile, User
    from core.db_connector import test_db_connection, get_db_columns
    import hashlib
    import yaml

    user_info = request.session.get('user', {})
    user = User.objects.filter(username=user_info.get('username')).first()

    pipeline_id = data.get("pipeline_id")
    profile_name = data.get("profile_name")
    save_to_pipeline = bool(data.get("save_to_pipeline", False))

    p_obj = None
    if pipeline_id:
        p_obj = Pipeline.objects.filter(id=pipeline_id).first()
        if not p_obj:
            return JsonResponse({"detail": f"Pipeline '{pipeline_id}' not found."}, status=404)
        if user and user.organization and p_obj.organization_id != user.organization_id:
            if user.role not in ['admin', 'subadmin']:
                return JsonResponse({"detail": "Unauthorized to inspect this pipeline."}, status=403)

        db_type = p_obj.db_type
        conn_str = p_obj.conn_str
        schema = p_obj.schema
        table = p_obj.table
    elif profile_name:
        profile = None
        if user and user.organization:
            profile = ConnectionProfile.objects.filter(name=profile_name, organization=user.organization).first()
        if not profile:
            profile = ConnectionProfile.objects.filter(name=profile_name).first()
        if not profile:
            return JsonResponse({"detail": f"Connection profile '{profile_name}' not found."}, status=404)
        db_type = profile.db_type
        conn_str = profile.connection_string
        schema = data.get("schema") or "public"
        table = data.get("table") or "orders"
    else:
        db_type = data.get("db_type") or data.get("dbType") or "postgres"
        conn_str = data.get("conn_str") or data.get("connStr") or ""
        schema = data.get("schema") or "public"
        table = data.get("table") or "orders"

    if not conn_str:
        return JsonResponse({"detail": "A connection string, profile, or pipeline ID is required."}, status=400)

    resolved_conn = resolve_connection_string(conn_str, db_type)
    columns = []
    connection_warning = None

    # Attempt live inspection
    try:
        ok, msg = test_db_connection(db_type, resolved_conn)
        if ok:
            schema_info = get_db_columns(db_type, resolved_conn, schema, table)
            columns = schema_info.get("columns", [])
        else:
            connection_warning = msg
    except Exception as e:
        connection_warning = str(e)

    # Fallback to existing pipeline contract/schema if live connection was unavailable
    if not columns and p_obj:
        if getattr(p_obj, 'contract_yaml', None):
            try:
                cfg = yaml.safe_load(p_obj.contract_yaml)
                if isinstance(cfg, dict) and cfg.get("columns"):
                    for c in cfg["columns"]:
                        columns.append({
                            "name": c.get("name"),
                            "type": c.get("type", "varchar(255)"),
                            "nullable": c.get("nullable", True),
                            "primary_key": bool(c.get("primary_key", False))
                        })
            except Exception:
                pass
        if not columns and getattr(p_obj, 'schema_map', None):
            s_cols = p_obj.schema_map.get("columns") or p_obj.schema_map.get("left") or []
            for c in s_cols:
                columns.append({
                    "name": c.get("name"),
                    "type": c.get("type", "varchar(255)"),
                    "nullable": not c.get("notNull", False),
                    "primary_key": bool(c.get("pk", False))
                })

    if not columns:
        err_msg = connection_warning or f"No columns could be inspected from table '{schema}.{table}'."
        return JsonResponse({
            "status": "failed",
            "detail": f"Database introspection error: {err_msg}"
        }, status=400)

    # Build canonical contract artifacts
    org_title = user.organization.name if (user and user.organization) else "Schema Guard Production"
    table_pascal = ''.join(word.capitalize() for word in table.replace('-', '_').split('_')) or 'DataRecord'
    
    # 1. Deterministic Contract Signature (SHA-256)
    sig_seed = f"{db_type.lower()}:{schema.lower()}:{table.lower()}:" + ";".join(
        f"{c['name'].lower()}:{c['type'].lower()}:{c.get('nullable', True)}:{c.get('primary_key', False)}"
        for c in columns
    )
    contract_signature = hashlib.sha256(sig_seed.encode('utf-8')).hexdigest()

    # 2. Canonical Production YAML
    from django.utils import timezone
    now_str = timezone.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    yaml_lines = [
        "# ============================================================",
        f"# Schema Guard Production Data Contract",
        f"# Reverse-Engineered: {now_str}",
        f"# Organization: {org_title}",
        f"# Target: {schema}.{table} ({db_type.upper()})",
        f"# 🔒 SHA-256 Lock Signature: {contract_signature}",
        "# ============================================================",
        "version: 1",
        "source:",
        f"  name: {table}_contract",
        f"  type: {db_type.lower()}",
        '  connection: "env:DB_CONNECTION_STRING"',
        f"  schema: {schema}",
        f"  table: {table}",
        "",
        "policy:",
        "  breaking_change_threshold: strict",
        "  allow_type_widening: false",
        "  allow_nullable_expansion: false",
        "  allow_drop_column: false",
        "",
        "columns:"
    ]
    for c in columns:
        yaml_lines.append(f"  - name: {c['name']}")
        yaml_lines.append(f"    type: {c['type']}")
        yaml_lines.append(f"    nullable: {'true' if c.get('nullable', True) else 'false'}")
        if c.get('primary_key'):
            yaml_lines.append("    primary_key: true")

    contract_yaml_str = "\n".join(yaml_lines) + "\n"

    # 3. Pydantic Model (Python SDK)
    pydantic_lines = [
        f"# Python Pydantic Model - {table_pascal} Contract",
        "from typing import Optional",
        "from decimal import Decimal",
        "from datetime import datetime, date",
        "from pydantic import BaseModel, Field",
        "",
        f"class {table_pascal}ContractModel(BaseModel):"
    ]
    for c in columns:
        t_low = c['type'].lower()
        if any(x in t_low for x in ['int', 'serial']):
            py_type = 'int'
        elif any(x in t_low for x in ['numeric', 'decimal', 'double', 'float', 'real']):
            py_type = 'Decimal'
        elif 'bool' in t_low:
            py_type = 'bool'
        elif 'timestamp' in t_low or 'datetime' in t_low:
            py_type = 'datetime'
        elif 'date' in t_low:
            py_type = 'date'
        else:
            py_type = 'str'
        
        is_null = c.get('nullable', True)
        field_annot = f"Optional[{py_type}] = None" if is_null else py_type
        pydantic_lines.append(f"    {c['name']}: {field_annot}")
    pydantic_code_str = "\n".join(pydantic_lines)

    # 4. TypeScript Interface
    ts_lines = [
        f"// TypeScript Definition - {table_pascal} Contract",
        f"export interface I{table_pascal}Contract {{"
    ]
    for c in columns:
        t_low = c['type'].lower()
        if any(x in t_low for x in ['int', 'serial', 'numeric', 'decimal', 'double', 'float', 'real']):
            ts_type = 'number'
        elif 'bool' in t_low:
            ts_type = 'boolean'
        elif any(x in t_low for x in ['date', 'time']):
            ts_type = 'Date | string'
        else:
            ts_type = 'string'
        is_null = c.get('nullable', True)
        ts_lines.append(f"    {c['name']}{'?' if is_null else ''}: {ts_type}{' | null' if is_null else ''};")
    ts_lines.append("}")
    ts_code_str = "\n".join(ts_lines)

    # 5. SQL DDL
    ddl_lines = [f"CREATE TABLE {schema}.{table} ("]
    col_defs = []
    for c in columns:
        null_clause = "" if c.get('nullable', True) else " NOT NULL"
        pk_clause = " PRIMARY KEY" if c.get('primary_key') else ""
        col_defs.append(f"    {c['name']} {c['type'].upper()}{null_clause}{pk_clause}")
    ddl_lines.append(",\n".join(col_defs))
    ddl_lines.append(");")
    sql_ddl_str = "\n".join(ddl_lines)

    # UI columns list for interactive editing table
    ui_columns = [
        {
            "name": c["name"],
            "type": c["type"],
            "notNull": not c.get("nullable", True),
            "pk": bool(c.get("primary_key", False)),
            "allowedDrift": ""
        }
        for c in columns
    ]

    # Save directly to pipeline if requested
    saved = False
    if save_to_pipeline and p_obj:
        p_obj.contract_yaml = contract_yaml_str
        p_obj.lock_signature = contract_signature
        p_obj.status = 'Clean'
        p_obj.schema_map = {"columns": ui_columns}
        p_obj.save(update_fields=['contract_yaml', 'lock_signature', 'status', 'schema_map'])
        saved = True
        record_contract_version(p_obj, request.session.get('user', {}).get('username', 'system'), "Reverse-engineered schema contract baseline")

    # Audit Logging
    log_action(
        request,
        'contract.reverse_engineered',
        'pipeline' if p_obj else 'table',
        str(p_obj.id) if p_obj else f"{schema}.{table}",
        {
            'columns_count': len(columns),
            'db_type': db_type,
            'schema': schema,
            'table': table,
            'saved': saved,
            'signature': contract_signature
        }
    )

    return JsonResponse({
        "status": "success",
        "pipeline_id": p_obj.id if p_obj else None,
        "pipeline_name": p_obj.name if p_obj else f"{schema}.{table}",
        "db_type": db_type,
        "schema": schema,
        "table": table,
        "columns": ui_columns,
        "contract_yaml": contract_yaml_str,
        "signature": contract_signature,
        "pydantic_code": pydantic_code_str,
        "typescript_code": ts_code_str,
        "sql_ddl": sql_ddl_str,
        "saved": saved,
        "message": f"Successfully reverse-engineered contract with {len(columns)} columns and locked SHA-256 signature!"
    })

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

def ci_cd_gate_api(request):
    """
    Unified CI/CD Data Contract Gate API for GitHub Actions, GitLab CI, and automation.
    Validates PR schema or DDL changes against verified contract specifications.
    Returns breaking status, violations list, exit code, and formatted PR markdown.
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    from core.models import Pipeline, ApiKey, GateValidationLog
    from django.utils import timezone as dj_tz

    # 1. Authenticate via API Key or active user session
    auth_header = request.headers.get("X-Schema-Guard-Token") or request.headers.get("Authorization") or request.GET.get("token")
    if auth_header and auth_header.startswith("Bearer "):
        auth_header = auth_header[7:].strip()

    authenticated = False
    org_id = None
    actor = "system/ci"

    if auth_header:
        token_hash = hash_api_key(auth_header)
        api_key = ApiKey.objects.filter(key_hash=token_hash, is_active=True).first()
        if api_key:
            authenticated = True
            org_id = api_key.organization_id
            actor = f"api_key:{api_key.name}"
            api_key.last_used_at = dj_tz.now()
            api_key.save(update_fields=['last_used_at'])

    if not authenticated and request.session.get('user'):
        u = request.session.get('user')
        authenticated = True
        org_id = u.get('organization_id')
        actor = u.get('username', 'user')

    if not authenticated:
        return JsonResponse({
            "detail": "Unauthorized: Missing or invalid API key. Pass 'X-Schema-Guard-Token' header or 'Authorization: Bearer <token>'."
        }, status=401)

    try:
        data = json.loads(request.body) if request.body else {}
    except Exception:
        data = {}

    pipeline_id = data.get("pipeline_id")
    table_name = data.get("table")
    db_schema = data.get("db_schema") or (data.get("schema") if isinstance(data.get("schema"), str) else None)
    environment = (data.get("environment") or "prod").lower()

    # Resolve target pipeline
    p_obj = None
    if pipeline_id:
        p_obj = Pipeline.objects.filter(id=pipeline_id).first()
    elif table_name:
        q = Pipeline.objects.filter(table__iexact=table_name)
        if org_id:
            q = q.filter(organization_id=org_id)
        if db_schema:
            q = q.filter(schema__iexact=db_schema)
        if environment:
            p_obj = q.filter(environment=environment).first()
        if not p_obj:
            p_obj = q.first()

    if not p_obj:
        return JsonResponse({
            "detail": f"Target pipeline not found for identifier '{pipeline_id or table_name}'."
        }, status=404)

    # Scoping check
    if org_id and p_obj.organization_id and p_obj.organization_id != org_id:
        return JsonResponse({"detail": "Unauthorized access to this pipeline."}, status=403)

    commit_sha = data.get("commit_sha", "").strip()
    branch = data.get("branch", "").strip()
    proposed_schema = data.get("proposed_schema") or (data.get("schema") if isinstance(data.get("schema"), dict) else None)
    proposed_ddl = data.get("ddl")

    # Load contract columns
    from core.migration_generator import parse_contract_columns
    contract_cols = parse_contract_columns(p_obj.contract_yaml)

    if not contract_cols:
        contract_path, _ = ensure_contract_and_snapshot_files(p_obj)
        if contract_path and os.path.exists(contract_path):
            try:
                cfg = load_contract(contract_path)
                contract_cols = cfg.get("columns", [])
            except Exception:
                pass

    if not contract_cols:
        return JsonResponse({
            "detail": f"Pipeline '{p_obj.name}' does not have a defined contract baseline. Please lock a contract first."
        }, status=400)

    # Resolve proposed columns
    proposed_cols = []
    if proposed_schema and isinstance(proposed_schema, dict) and "columns" in proposed_schema:
        proposed_cols = proposed_schema["columns"]
    elif proposed_ddl:
        sim_cols = list(contract_cols)
        add_matches = re.findall(r'add\s+(?:column\s+)?([a-zA-Z0-9_]+)\s+([a-zA-Z0-9_\(\)]+)', proposed_ddl, re.I)
        for m_col, m_type in add_matches:
            sim_cols.append({"name": m_col, "type": m_type, "nullable": "not null" not in proposed_ddl.lower()})
        drop_matches = re.findall(r'drop\s+column\s+([a-zA-Z0-9_]+)', proposed_ddl, re.I)
        for m_col in drop_matches:
            sim_cols = [c for c in sim_cols if c["name"].lower() != m_col.lower()]
        proposed_cols = sim_cols
    else:
        try:
            resolved_conn = resolve_connection_string(p_obj.conn_str, p_obj.db_type)
            from core.db_connector import get_db_columns
            live_info = get_db_columns(p_obj.db_type, resolved_conn, p_obj.schema, p_obj.table)
            proposed_cols = live_info.get("columns", [])
        except Exception as e:
            return JsonResponse({"detail": f"Could not extract live schema for gate check: {e}"}, status=400)

    # Evaluate contract rules
    from core.ci_gate import evaluate_proposed_schema_against_contract, build_github_markdown_report
    violations, warnings = evaluate_proposed_schema_against_contract(contract_cols, proposed_cols)

    is_passed = (len(violations) == 0)
    status_str = "PASSED" if is_passed else "BLOCKED"
    exit_code = 0 if is_passed else 1

    # Build Markdown PR report
    md_report = build_github_markdown_report(
        pipeline_name=p_obj.name,
        table=p_obj.table,
        schema=p_obj.schema,
        environment=p_obj.environment or 'prod',
        status=status_str,
        violations=violations,
        warnings=warnings,
        commit_sha=commit_sha,
        branch=branch
    )

    # Log in GateValidationLog
    log_entry = GateValidationLog.objects.create(
        pipeline=p_obj,
        commit_sha=commit_sha,
        branch=branch,
        status="PASS" if is_passed else "FAIL",
        violations_count=len(violations),
        details={
            "violations": violations,
            "warnings": warnings,
            "actor": actor,
            "total_columns": len(proposed_cols)
        }
    )

    summary_text = (
        f"✅ PASSED: All {len(proposed_cols)} schema columns comply with contract baseline."
        if is_passed
        else f"❌ BLOCKED: {len(violations)} breaking schema contract violation(s) detected."
    )

    return JsonResponse({
        "passed": is_passed,
        "status": status_str,
        "exit_code": exit_code,
        "violations_count": len(violations),
        "warnings_count": len(warnings),
        "violations": violations,
        "warnings": warnings,
        "summary": summary_text,
        "pipeline": {
            "id": p_obj.id,
            "name": p_obj.name,
            "table": p_obj.table,
            "schema": p_obj.schema,
            "environment": p_obj.environment or 'prod',
            "lock_signature": p_obj.lock_signature
        },
        "github_markdown": md_report,
        "checked_at": log_entry.checked_at.isoformat()
    })


def ci_cd_workflow_template_api(request):
    """
    Generates ready-to-use CI/CD workflow templates (GitHub Actions, GitLab CI, Bash).
    """
    pipeline_id = request.GET.get("pipeline_id")
    platform = (request.GET.get("platform") or "github").lower()
    download = bool(request.GET.get("download"))

    from core.models import Pipeline
    p_obj = Pipeline.objects.filter(id=pipeline_id).first() if pipeline_id else None

    table_name = p_obj.table if p_obj else "orders"
    pid = p_obj.id if p_obj else "pipe-orders-demo"
    base_url = f"{request.scheme}://{request.get_host()}"

    from core.ci_gate import generate_ci_workflow_template
    tmpl = generate_ci_workflow_template(
        platform=platform,
        base_url=base_url,
        pipeline_id=pid,
        table_name=table_name
    )

    if download:
        content_type = "text/yaml" if "yml" in tmpl["filename"] else "text/plain"
        response = HttpResponse(tmpl["content"], content_type=f"{content_type}; charset=utf-8")
        response['Content-Disposition'] = f'attachment; filename="{os.path.basename(tmpl["filename"])}"'
        return response

    return JsonResponse(tmpl)


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
def get_webhook_logs_api(request, id):
    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user')
    from core.models import Pipeline, WebhookDeliveryLog
    p_obj = Pipeline.objects.filter(id=id).first()
    if not p_obj:
        return JsonResponse({"detail": "Pipeline not found"}, status=404)

    if user_info.get('role') != 'admin' and p_obj.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    logs_qs = WebhookDeliveryLog.objects.filter(pipeline=p_obj).order_by('-created_at')[:50]
    logs_data = [{
        "id": log.id,
        "url": log.url,
        "webhook_type": log.webhook_type,
        "event": log.event,
        "status_code": log.status_code,
        "request_headers": log.request_headers,
        "request_payload": log.request_payload,
        "response_body": log.response_body,
        "latency_ms": log.latency_ms,
        "success": log.success,
        "error_message": log.error_message,
        "retry_count": log.retry_count,
        "created_at": log.created_at.strftime("%Y-%m-%d %H:%M:%S")
    } for log in logs_qs]

    return JsonResponse(logs_data, safe=False)


@require_login
def retry_webhook_log_api(request, id, log_id):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user')
    from core.models import Pipeline, WebhookDeliveryLog, AuditLog
    from core.notifications import dispatch_signed_webhook
    from django.conf import settings

    p_obj = Pipeline.objects.filter(id=id).first()
    if not p_obj:
        return JsonResponse({"detail": "Pipeline not found"}, status=404)

    if user_info.get('role') != 'admin' and p_obj.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    log_entry = WebhookDeliveryLog.objects.filter(id=log_id, pipeline=p_obj).first()
    if not log_entry:
        return JsonResponse({"detail": "Webhook log not found"}, status=404)

    alerts_cfg = p_obj.alerts or {}
    secret = alerts_cfg.get("webhook_secret")
    allow_internal = getattr(settings, 'IS_TESTING', False)

    ok, reason, meta = dispatch_signed_webhook(
        url=log_entry.url,
        payload=log_entry.request_payload,
        secret=secret,
        event=log_entry.event,
        pipeline=p_obj,
        max_retries=1,
        webhook_type=log_entry.webhook_type,
        allow_internal=allow_internal
    )

    actor = user_info.get('username') or 'user'
    AuditLog.objects.create(
        action='webhook.delivery',
        actor=actor,
        target_type='pipeline',
        target_id=str(p_obj.id),
        organization=p_obj.organization,
        details={
            "action": "retry_webhook",
            "previous_log_id": log_id,
            "new_log_id": meta.get("log_id"),
            "success": ok,
            "status_code": meta.get("status_code"),
            "url": log_entry.url
        }
    )

    return JsonResponse({
        "success": ok,
        "message": reason,
        "meta": meta
    }, status=200 if ok else 502)

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
        err_msg = str(e).strip() or repr(e) or "Pipeline not found or validation check failed."
        return JsonResponse({"detail": err_msg}, status=404)
    except Exception as e:
        err_msg = str(e).strip() or repr(e) or type(e).__name__ or "Unknown pipeline check failure."
        return JsonResponse({"detail": err_msg}, status=400)

@require_login
def generate_pipeline_migration_api(request, id):
    """
    Automated Schema Migration Script Generator API.
    Computes schema drift between locked contract and live database,
    and returns forward (UP) and rollback (DOWN) migration scripts
    for SQL, Flyway, Liquibase, and Alembic.
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    from core.models import Pipeline
    p_obj = Pipeline.objects.filter(id=id).first()
    if not p_obj:
        return JsonResponse({"detail": "Pipeline not found."}, status=404)

    if user_info.get('role') != 'admin' and p_obj.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    try:
        data = json.loads(request.body) if request.body else {}
    except Exception:
        data = {}

    target_engine = data.get("target_engine") or p_obj.db_type

    from core.migration_generator import generate_migration_bundle
    bundle = generate_migration_bundle(p_obj, target_engine=target_engine)
    return JsonResponse(bundle)


@require_login
def auto_repair_pipeline_api(request, id):
    """
    1-Click Safe Automated Database Repair API with DDL Safety Gating.
    Generates alignment DDL, blocks destructive changes (unless explicitly authorized),
    applies safe DDL directly against the live database connection, re-verifies schema status,
    and records an immutable AuditLog entry.
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    from core.models import Pipeline, AuditLog
    p_obj = Pipeline.objects.filter(id=id).first()
    if not p_obj:
        return JsonResponse({"detail": "Pipeline not found."}, status=404)

    # Enforce organization and edit permission boundary
    if user_info.get('role') != 'admin' and p_obj.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    user_perms = user_info.get('permissions', {})
    if user_info.get('role') not in ('admin', 'subadmin') and not user_perms.get('edit', True):
        return JsonResponse({"detail": "Forbidden: Requires edit permission to apply database migrations."}, status=403)

    try:
        data = json.loads(request.body) if request.body else {}
    except Exception:
        data = {}

    dry_run = bool(data.get("dry_run", False))
    allow_destructive = bool(data.get("allow_destructive", False))
    target_engine = data.get("target_engine") or p_obj.db_type

    from core.migration_generator import generate_migration_bundle
    bundle = generate_migration_bundle(p_obj, target_engine=target_engine)

    if bundle.get("diff_count", 0) == 0:
        return JsonResponse({
            "success": True,
            "repaired": False,
            "message": "Schema is already in full alignment with the locked contract. No repair needed.",
            "executed_statements": [],
            "risk_summary": bundle.get("risk_summary", {})
        })

    risk_summary = bundle.get("risk_summary", {})
    breaking_count = risk_summary.get("breaking", 0)

    # Safety Gating: Reject destructive operations unless explicitly requested
    if breaking_count > 0 and not allow_destructive:
        return JsonResponse({
            "detail": f"Safety Guard: {breaking_count} destructive/breaking change(s) detected. Auto-repair blocked to protect against data loss. Pass allow_destructive=true to authorize this execution.",
            "risk_summary": risk_summary,
            "breaking_diffs": [d for d in bundle.get("diffs", []) if d.get("risk") == "BREAKING"]
        }, status=400)

    raw_sql = bundle.get("sql", {}).get("up", "")
    statements = []
    for line in raw_sql.split(";"):
        stmt = line.strip()
        cleaned = "\n".join([l for l in stmt.splitlines() if not l.strip().startswith("--")]).strip()
        if cleaned:
            statements.append(cleaned)

    if not statements:
        return JsonResponse({
            "success": True,
            "repaired": False,
            "message": "No actionable DDL statements to execute.",
            "executed_statements": []
        })

    if dry_run:
        return JsonResponse({
            "success": True,
            "dry_run": True,
            "statements_to_execute": statements,
            "risk_summary": risk_summary,
            "message": f"Dry-run preview: {len(statements)} DDL statement(s) analyzed and validated for execution."
        })

    # Execute against live database
    import sqlalchemy
    resolved_conn = resolve_connection_string(p_obj.conn_str, p_obj.db_type)
    executed_stmts = []

    try:
        engine, _ = create_db_engine(p_obj.db_type, resolved_conn, timeout=15)
        with engine.begin() as conn:
            for s in statements:
                conn.execute(sqlalchemy.text(s))
                executed_stmts.append(s)
        engine.dispose()
    except Exception as e:
        logger.error(f"Auto-repair execution failed for pipeline {p_obj.id}: {e}")
        return JsonResponse({
            "detail": f"Database DDL execution failed: {str(e)}",
            "partially_executed": executed_stmts
        }, status=500)

    # Re-evaluate pipeline status
    recheck_result = perform_pipeline_check(p_obj.id)

    # Audit Logging
    actor = user_info.get('username') or 'user'
    AuditLog.objects.create(
        action='pipeline.auto_repaired',
        actor=actor,
        target_type='pipeline',
        target_id=str(p_obj.id),
        organization=p_obj.organization,
        details={
            "executed_statements": executed_stmts,
            "risk_summary": risk_summary,
            "allow_destructive": allow_destructive,
            "recheck_status": recheck_result.get("status") if isinstance(recheck_result, dict) else str(recheck_result)
        }
    )

    return JsonResponse({
        "success": True,
        "repaired": True,
        "executed_statements": executed_stmts,
        "risk_summary": risk_summary,
        "recheck_result": recheck_result,
        "message": f"Successfully executed {len(executed_stmts)} DDL statement(s). Target database synchronized!"
    })


@require_login
def download_pipeline_migration_api(request, id):
    """
    Direct file download endpoint for generated schema migration scripts.
    Supports formats: sql_up, sql_down, flyway_v, flyway_u, liquibase, alembic.
    """
    if request.method != "GET":
        return HttpResponse("Method not allowed", status=405)

    user_info = request.session.get('user', {})
    from core.models import Pipeline
    p_obj = Pipeline.objects.filter(id=id).first()
    if not p_obj:
        return HttpResponse("Pipeline not found", status=404)

    if user_info.get('role') != 'admin' and p_obj.organization_id != user_info.get('organization_id'):
        return HttpResponse("Unauthorized", status=403)

    target_engine = request.GET.get("target_engine") or p_obj.db_type
    fmt = (request.GET.get("format") or "sql_up").lower()

    from core.migration_generator import generate_migration_bundle
    bundle = generate_migration_bundle(p_obj, target_engine=target_engine)

    if fmt == "sql_up":
        filename = bundle["sql"]["filename_up"]
        content = bundle["sql"]["up"]
        content_type = "text/x-sql; charset=utf-8"
    elif fmt == "sql_down":
        filename = bundle["sql"]["filename_down"]
        content = bundle["sql"]["down"]
        content_type = "text/x-sql; charset=utf-8"
    elif fmt == "flyway_v":
        filename = bundle["flyway"]["versioned_filename"]
        content = bundle["flyway"]["versioned_sql"]
        content_type = "text/x-sql; charset=utf-8"
    elif fmt == "flyway_u":
        filename = bundle["flyway"]["undo_filename"]
        content = bundle["flyway"]["undo_sql"]
        content_type = "text/x-sql; charset=utf-8"
    elif fmt == "liquibase":
        filename = bundle["liquibase"]["filename"]
        content = bundle["liquibase"]["yaml"]
        content_type = "text/yaml; charset=utf-8"
    elif fmt == "alembic":
        filename = bundle["alembic"]["filename"]
        content = bundle["alembic"]["python"]
        content_type = "text/x-python; charset=utf-8"
    else:
        filename = bundle["sql"]["filename_up"]
        content = bundle["sql"]["up"]
        content_type = "text/x-sql; charset=utf-8"

    response = HttpResponse(content, content_type=content_type)
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


def record_contract_version(pipeline, actor_username: str, change_summary: str = "Contract baseline update"):
    """Creates a new immutable ContractVersion snapshot for the given pipeline."""
    from core.models import ContractVersion
    if not pipeline or not pipeline.contract_yaml:
        return None

    last_version = ContractVersion.objects.filter(pipeline=pipeline).order_by('-version_number').first()
    next_ver = (last_version.version_number + 1) if last_version else 1

    # Don't create duplicate if content and signature are identical to last_version
    if last_version and last_version.contract_yaml == pipeline.contract_yaml and last_version.lock_signature == pipeline.lock_signature:
        return last_version

    cv = ContractVersion.objects.create(
        pipeline=pipeline,
        version_number=next_ver,
        contract_yaml=pipeline.contract_yaml,
        lock_signature=pipeline.lock_signature or '',
        schema_map=pipeline.schema_map or {},
        change_summary=change_summary,
        created_by=actor_username or 'system'
    )
    return cv


@require_login
def list_contract_versions_api(request, id):
    """
    List all immutable contract versions for a given pipeline.
    """
    user_info = request.session.get('user', {})
    from core.models import Pipeline, ContractVersion
    pipeline = Pipeline.objects.filter(id=id).first()
    if not pipeline:
        return JsonResponse({"detail": "Pipeline not found."}, status=404)

    if user_info.get('role') != 'admin' and pipeline.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    versions = list(ContractVersion.objects.filter(pipeline=pipeline).order_by('-version_number'))

    # Auto-seed v1 baseline if versions empty but contract exists
    if not versions and pipeline.contract_yaml:
        v1 = record_contract_version(pipeline, 'system', 'Initial baseline contract')
        if v1:
            versions = [v1]

    data = []
    for v in versions:
        is_active = (v.contract_yaml == pipeline.contract_yaml and v.lock_signature == pipeline.lock_signature)
        data.append({
            "id": str(v.id),
            "version_number": v.version_number,
            "signature": v.lock_signature,
            "change_summary": v.change_summary,
            "created_by": v.created_by,
            "created_at": v.created_at.isoformat(),
            "is_active": is_active,
            "columns_count": len(v.schema_map.get("columns", [])) if isinstance(v.schema_map, dict) and "columns" in v.schema_map else 0
        })

    return JsonResponse({
        "success": True,
        "pipeline_id": pipeline.id,
        "pipeline_name": pipeline.name,
        "current_signature": pipeline.lock_signature,
        "versions": data
    })


@require_login
def get_pipeline_timeline_api(request, id):
    """
    Time-Travel Timeline API:
    Aggregates SchemaSnapshots, ContractVersions, DriftIncidents, and AuditLog events
    into a chronological unified event stream for visual point-in-time schema governance.
    """
    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    from core.models import Pipeline, SchemaSnapshot, ContractVersion, DriftIncident, AuditLog
    pipeline = Pipeline.objects.filter(id=id).first()
    if not pipeline:
        return JsonResponse({"detail": "Pipeline not found."}, status=404)

    if user_info.get('role') != 'admin' and pipeline.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    events = []

    # 1. Schema Snapshots (live database structural state captures)
    snapshots = SchemaSnapshot.objects.filter(pipeline=pipeline).order_by('-captured_at')[:50]
    for s in snapshots:
        col_count = len(s.schema_data.get("columns", [])) if isinstance(s.schema_data, dict) and "columns" in s.schema_data else (len(s.schema_data) if isinstance(s.schema_data, dict) else 0)
        events.append({
            "event_type": "snapshot",
            "timestamp": s.captured_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "raw_timestamp": s.captured_at.isoformat(),
            "actor": s.captured_by or "system",
            "title": f"Database Schema Snapshot v{s.version}",
            "description": f"Captured {col_count} columns • Status: {s.status} ({s.violations_count} violations)",
            "status": s.status,
            "badge_color": "emerald" if s.status == "Clean" else "rose",
            "snapshot_id": s.id,
            "version": s.version,
            "columns_count": col_count,
            "hash": s.hash[:16] if s.hash else None,
        })

    # 2. Contract Versions (governance contract baseline locks & revisions)
    versions = ContractVersion.objects.filter(pipeline=pipeline).order_by('-created_at')[:30]
    for v in versions:
        events.append({
            "event_type": "contract_version",
            "timestamp": v.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "raw_timestamp": v.created_at.isoformat(),
            "actor": v.created_by or "engineer",
            "title": f"Data Contract Revision v{v.version_number}",
            "description": v.change_summary or "Contract baseline locked with cryptographic signature",
            "badge_color": "indigo",
            "version_number": v.version_number,
            "signature": v.lock_signature[:16] if v.lock_signature else None,
        })

    # 3. Drift Incidents (violations opened, acknowledged, resolved)
    incidents = DriftIncident.objects.filter(pipeline=pipeline).order_by('-created_at')[:30]
    for inc in incidents:
        events.append({
            "event_type": "incident",
            "timestamp": inc.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "raw_timestamp": inc.created_at.isoformat(),
            "actor": inc.acknowledged_by or "system",
            "title": f"Incident {inc.incident_number}: {inc.title}",
            "description": f"Severity: {inc.severity} • Status: {inc.status} ({inc.violations_count} violations)",
            "status": inc.status,
            "severity": inc.severity,
            "badge_color": "red" if inc.severity == "CRITICAL" else "amber",
            "incident_number": inc.incident_number,
            "mttr_seconds": inc.mttr_seconds,
        })

    # 4. Relevant Audit Logs (promotions, rollbacks, auto-repairs)
    audit_logs = AuditLog.objects.filter(
        models.Q(target_id=str(pipeline.id)) | models.Q(details__pipeline_id=str(pipeline.id))
    ).order_by('-timestamp')[:30]
    for a in audit_logs:
        if a.action in ('pipeline.promoted', 'contract.rollback', 'pipeline.auto_repaired'):
            action_label = {
                'pipeline.promoted': 'Multi-Environment Promotion',
                'contract.rollback': 'Contract Revision Rollback',
                'pipeline.auto_repaired': 'Safe Database Auto-Repair Executed'
            }.get(a.action, a.action)
            events.append({
                "event_type": "audit_action",
                "action": a.action,
                "timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "raw_timestamp": a.timestamp.isoformat(),
                "actor": a.actor,
                "title": action_label,
                "description": f"Actor: {a.actor} • Details: {json.dumps(a.details)}",
                "badge_color": "cyan",
                "details": a.details,
            })

    # Sort all events chronologically descending
    events.sort(key=lambda x: x["raw_timestamp"], reverse=True)

    return JsonResponse({
        "success": True,
        "pipeline_id": pipeline.id,
        "pipeline_name": pipeline.name,
        "environment": getattr(pipeline, "environment", "prod") or "prod",
        "current_status": pipeline.status,
        "total_events": len(events),
        "timeline": events
    })


@require_login
def diff_pipeline_timeline_api(request, id):
    """
    Time-Travel Diff Inspector:
    Computes a deep structural schema diff between two historical snapshots or versions.
    Accepts query parameters:
      - snap1, snap2: IDs of SchemaSnapshot
      - OR v1, v2: version numbers of ContractVersion
    """
    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    from core.models import Pipeline, SchemaSnapshot, ContractVersion
    pipeline = Pipeline.objects.filter(id=id).first()
    if not pipeline:
        return JsonResponse({"detail": "Pipeline not found."}, status=404)

    if user_info.get('role') != 'admin' and pipeline.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    snap1_id = request.GET.get('snap1')
    snap2_id = request.GET.get('snap2')
    v1_num = request.GET.get('v1')
    v2_num = request.GET.get('v2')

    def extract_cols_map(data):
        if not data:
            return {}
        if isinstance(data, dict):
            if "columns" in data and isinstance(data["columns"], list):
                out = {}
                for c in data["columns"]:
                    if isinstance(c, dict) and "name" in c:
                        out[c["name"]] = c.get("type", "varchar")
                    elif isinstance(c, str):
                        out[c] = "varchar"
                return out
            return {k: str(v) for k, v in data.items() if not k.startswith('_')}
        return {}

    if snap1_id and snap2_id:
        s1 = SchemaSnapshot.objects.filter(id=snap1_id, pipeline=pipeline).first()
        s2 = SchemaSnapshot.objects.filter(id=snap2_id, pipeline=pipeline).first()
        if not s1 or not s2:
            return JsonResponse({"detail": "One or both snapshots not found."}, status=404)
        schema1_map = extract_cols_map(s1.schema_data)
        schema2_map = extract_cols_map(s2.schema_data)
        meta1 = {"type": "snapshot", "version": s1.version, "timestamp": s1.captured_at.strftime("%Y-%m-%d %H:%M:%S UTC")}
        meta2 = {"type": "snapshot", "version": s2.version, "timestamp": s2.captured_at.strftime("%Y-%m-%d %H:%M:%S UTC")}
    elif v1_num and v2_num:
        cv1 = ContractVersion.objects.filter(version_number=v1_num, pipeline=pipeline).first()
        cv2 = ContractVersion.objects.filter(version_number=v2_num, pipeline=pipeline).first()
        if not cv1 or not cv2:
            return JsonResponse({"detail": "One or both contract versions not found."}, status=404)
        schema1_map = extract_cols_map(cv1.schema_map)
        schema2_map = extract_cols_map(cv2.schema_map)
        meta1 = {"type": "contract_version", "version": cv1.version_number, "timestamp": cv1.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")}
        meta2 = {"type": "contract_version", "version": cv2.version_number, "timestamp": cv2.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")}
    else:
        snaps = list(SchemaSnapshot.objects.filter(pipeline=pipeline).order_by('captured_at'))
        if len(snaps) >= 2:
            s1, s2 = snaps[0], snaps[-1]
            schema1_map = extract_cols_map(s1.schema_data)
            schema2_map = extract_cols_map(s2.schema_data)
            meta1 = {"type": "snapshot", "version": s1.version, "timestamp": s1.captured_at.strftime("%Y-%m-%d %H:%M:%S UTC")}
            meta2 = {"type": "snapshot", "version": s2.version, "timestamp": s2.captured_at.strftime("%Y-%m-%d %H:%M:%S UTC")}
        else:
            return JsonResponse({"detail": "Not enough historical snapshots or versions to compare. Run checks to generate snapshots."}, status=400)

    added_cols = []
    removed_cols = []
    altered_cols = []
    unchanged_count = 0

    all_keys = set(schema1_map.keys()) | set(schema2_map.keys())
    for col in sorted(all_keys):
        in_1 = col in schema1_map
        in_2 = col in schema2_map
        if in_2 and not in_1:
            added_cols.append({"name": col, "type": schema2_map[col]})
        elif in_1 and not in_2:
            removed_cols.append({"name": col, "type": schema1_map[col]})
        else:
            t1 = str(schema1_map[col]).lower()
            t2 = str(schema2_map[col]).lower()
            if t1 != t2:
                altered_cols.append({"name": col, "old_type": schema1_map[col], "new_type": schema2_map[col]})
            else:
                unchanged_count += 1

    return JsonResponse({
        "success": True,
        "pipeline_id": pipeline.id,
        "baseline": meta1,
        "target": meta2,
        "diff_summary": {
            "added_count": len(added_cols),
            "removed_count": len(removed_cols),
            "altered_count": len(altered_cols),
            "unchanged_count": unchanged_count,
            "has_breaking_changes": len(removed_cols) > 0
        },
        "added_columns": added_cols,
        "removed_columns": removed_cols,
        "altered_columns": altered_cols,
    })


@require_login
def pipeline_dq_rules_api(request, id):
    """
    Column-Level Data Quality Assertions API:
    GET: inspects all column quality rules (nullable, pk, allowed_values, min/max).
    POST: updates column quality assertions in the contract YAML and re-locks contract.
    """
    user_info = request.session.get('user', {})
    from core.models import Pipeline, AuditLog
    pipeline = Pipeline.objects.filter(id=id).first()
    if not pipeline:
        return JsonResponse({"detail": "Pipeline not found."}, status=404)

    if user_info.get('role') != 'admin' and pipeline.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    import yaml

    if request.method == "GET":
        contract_data = {}
        if pipeline.contract_yaml:
            try:
                contract_data = yaml.safe_load(pipeline.contract_yaml) or {}
            except Exception:
                contract_data = {}

        cols = contract_data.get("columns", [])
        rules = []
        for c in cols:
            if isinstance(c, dict):
                rules.append({
                    "column": c.get("name"),
                    "type": c.get("type", "varchar"),
                    "nullable": c.get("nullable", True),
                    "primary_key": c.get("primary_key", False),
                    "allowed_values": c.get("allowed_values") or c.get("enum") or [],
                    "min_value": c.get("min_value"),
                    "max_value": c.get("max_value"),
                })

        return JsonResponse({
            "success": True,
            "pipeline_id": pipeline.id,
            "pipeline_name": pipeline.name,
            "table": pipeline.table,
            "total_rules": len(rules),
            "rules": rules
        })

    elif request.method == "POST":
        user_perms = user_info.get('permissions', {})
        if user_info.get('role') not in ('admin', 'subadmin') and not user_perms.get('edit', True):
            return JsonResponse({"detail": "Forbidden: Requires edit permission to update contract rules."}, status=403)

        try:
            data = json.loads(request.body) if request.body else {}
        except Exception:
            return JsonResponse({"detail": "Invalid JSON body"}, status=400)

        updated_rules = data.get("rules", [])
        if not isinstance(updated_rules, list):
            return JsonResponse({"detail": "'rules' must be a list"}, status=400)

        contract_data = {}
        if pipeline.contract_yaml:
            try:
                contract_data = yaml.safe_load(pipeline.contract_yaml) or {}
            except Exception:
                contract_data = {}

        existing_cols = contract_data.get("columns", [])
        rules_by_col = {r.get("column"): r for r in updated_rules if isinstance(r, dict) and r.get("column")}

        new_cols = []
        for c in existing_cols:
            if isinstance(c, dict):
                col_name = c.get("name")
                if col_name in rules_by_col:
                    r = rules_by_col[col_name]
                    if "nullable" in r:
                        c["nullable"] = bool(r["nullable"])
                    if "primary_key" in r:
                        c["primary_key"] = bool(r["primary_key"])
                    if "allowed_values" in r:
                        c["allowed_values"] = r["allowed_values"]
                    if "min_value" in r:
                        c["min_value"] = r["min_value"]
                    if "max_value" in r:
                        c["max_value"] = r["max_value"]
                new_cols.append(c)

        contract_data["columns"] = new_cols
        new_yaml = yaml.dump(contract_data, sort_keys=False)

        pipeline.contract_yaml = new_yaml
        pipeline.save()

        contract_path, _ = ensure_contract_and_snapshot_files(pipeline)
        if contract_path:
            with open(contract_path, "w", encoding="utf-8") as f:
                f.write(new_yaml)

        new_sig = lock_contract(pipeline.id)
        if new_sig:
            pipeline.lock_signature = new_sig
            pipeline.save()

        actor = user_info.get('username') or 'user'
        from core.views import record_contract_version
        record_contract_version(pipeline, actor, f"Updated data quality assertions on {len(rules_by_col)} column(s)")

        AuditLog.objects.create(
            action='contract.lock',
            actor=actor,
            target_type='pipeline',
            target_id=str(pipeline.id),
            organization=pipeline.organization,
            details={
                "action": "update_dq_rules",
                "rules_updated": len(rules_by_col),
                "new_signature": new_sig
            }
        )

        return JsonResponse({
            "success": True,
            "message": f"Successfully updated data quality rules on {len(rules_by_col)} column(s). Contract baseline re-locked.",
            "pipeline_id": pipeline.id,
            "lock_signature": new_sig
        })

    return JsonResponse({"detail": "Method not allowed"}, status=405)


@require_login
def pipeline_alert_routing_api(request, id):
    """
    Multi-Channel Alert Routing Policy API:
    GET: returns current smart routing policy and rules matrix.
    POST: configures per-environment and per-severity alert routing for Slack, Teams, Email, Webhook.
    """
    user_info = request.session.get('user', {})
    from core.models import Pipeline, AuditLog
    pipeline = Pipeline.objects.filter(id=id).first()
    if not pipeline:
        return JsonResponse({"detail": "Pipeline not found."}, status=404)

    if user_info.get('role') != 'admin' and pipeline.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    alerts_cfg = pipeline.alerts or {}

    if request.method == "GET":
        routing = alerts_cfg.get("routing") or {
            "enabled": False,
            "rules": []
        }
        return JsonResponse({
            "success": True,
            "pipeline_id": pipeline.id,
            "pipeline_name": pipeline.name,
            "environment": getattr(pipeline, "environment", "prod") or "prod",
            "routing": routing,
            "legacy_alerts": {k: v for k, v in alerts_cfg.items() if k != "routing"}
        })

    elif request.method == "POST":
        user_perms = user_info.get('permissions', {})
        if user_info.get('role') not in ('admin', 'subadmin') and not user_perms.get('edit', True):
            return JsonResponse({"detail": "Forbidden: Requires edit permission to configure alert policies."}, status=403)

        try:
            data = json.loads(request.body) if request.body else {}
        except Exception:
            return JsonResponse({"detail": "Invalid JSON body"}, status=400)

        enabled = bool(data.get("enabled", True))
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            return JsonResponse({"detail": "'rules' must be a list of routing rule objects"}, status=400)

        cleaned_rules = []
        for r in rules:
            if isinstance(r, dict) and r.get("channel") and r.get("target"):
                cleaned_rules.append({
                    "channel": str(r["channel"]).lower().strip(),
                    "target": str(r["target"]).strip(),
                    "min_severity": str(r.get("min_severity", "LOW")).upper().strip(),
                    "environments": [str(e).lower().strip() for e in r.get("environments", ["*"])]
                })

        new_alerts = dict(alerts_cfg)
        new_alerts["routing"] = {
            "enabled": enabled,
            "rules": cleaned_rules
        }
        pipeline.alerts = new_alerts
        pipeline.save()

        from schema_guard import db
        db.update_pipeline(pipeline.id, {"alerts": new_alerts})

        actor = user_info.get('username') or 'user'
        AuditLog.objects.create(
            action='contract.lock',
            actor=actor,
            target_type='pipeline',
            target_id=str(pipeline.id),
            organization=pipeline.organization,
            details={
                "action": "update_alert_routing",
                "enabled": enabled,
                "rules_count": len(cleaned_rules)
            }
        )

        return JsonResponse({
            "success": True,
            "message": f"Successfully updated alert routing policy with {len(cleaned_rules)} rule(s).",
            "pipeline_id": pipeline.id,
            "routing": new_alerts["routing"]
        })

    return JsonResponse({"detail": "Method not allowed"}, status=405)


@require_login
def get_contract_version_detail_api(request, id, version_number):
    """
    Retrieve full details and YAML content for a specific contract version.
    """
    user_info = request.session.get('user', {})
    from core.models import Pipeline, ContractVersion
    pipeline = Pipeline.objects.filter(id=id).first()
    if not pipeline:
        return JsonResponse({"detail": "Pipeline not found."}, status=404)

    if user_info.get('role') != 'admin' and pipeline.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    cv = ContractVersion.objects.filter(pipeline=pipeline, version_number=version_number).first()
    if not cv:
        return JsonResponse({"detail": f"Version v{version_number} not found for this pipeline."}, status=404)

    return JsonResponse({
        "success": True,
        "pipeline_id": pipeline.id,
        "version_number": cv.version_number,
        "contract_yaml": cv.contract_yaml,
        "lock_signature": cv.lock_signature,
        "schema_map": cv.schema_map,
        "change_summary": cv.change_summary,
        "created_by": cv.created_by,
        "created_at": cv.created_at.isoformat(),
        "is_active": (cv.contract_yaml == pipeline.contract_yaml and cv.lock_signature == pipeline.lock_signature)
    })


@require_login
def rollback_contract_version_api(request, id, version_number):
    """
    Rolls back pipeline contract to a specific previous version.
    Restores YAML, signature, schema map, resets status to Clean, and records a new version snapshot.
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    if user_info.get('role') not in ['admin', 'subadmin', 'operator']:
        return JsonResponse({"detail": "Permission denied: Contract rollback requires Admin, Subadmin, or Operator role."}, status=403)

    from core.models import Pipeline, ContractVersion
    pipeline = Pipeline.objects.filter(id=id).first()
    if not pipeline:
        return JsonResponse({"detail": "Pipeline not found."}, status=404)

    if user_info.get('role') != 'admin' and pipeline.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    target_v = ContractVersion.objects.filter(pipeline=pipeline, version_number=version_number).first()
    if not target_v:
        return JsonResponse({"detail": f"Contract version v{version_number} not found."}, status=404)

    # Roll back pipeline state
    pipeline.contract_yaml = target_v.contract_yaml
    pipeline.lock_signature = target_v.lock_signature
    pipeline.schema_map = target_v.schema_map
    pipeline.status = 'Clean'
    pipeline.save(update_fields=['contract_yaml', 'lock_signature', 'schema_map', 'status'])

    # Create new ContractVersion recording the rollback
    username = user_info.get('username', 'system')
    new_cv = record_contract_version(
        pipeline,
        username,
        f"Rollback to contract v{version_number}"
    )

    # Audit Log
    log_action(
        request,
        'contract.rollback',
        'pipeline',
        pipeline.id,
        {
            'restored_version': version_number,
            'new_version': new_cv.version_number if new_cv else None,
            'lock_signature': pipeline.lock_signature
        }
    )

    return JsonResponse({
        "success": True,
        "message": f"Successfully rolled back contract to v{version_number}.",
        "restored_version": version_number,
        "new_version": new_cv.version_number if new_cv else version_number,
        "lock_signature": pipeline.lock_signature
    })


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

    # Rate Limiting: protect Gemini LLM quota (max 20 queries / min per user)
    from django.core.cache import cache
    rate_key = f"ai_diag_rate_{user_info.get('username', 'anon')}"
    query_count = cache.get(rate_key, 0)
    if query_count >= 20:
        return JsonResponse({
            "detail": "AI Copilot query rate limit reached (max 20 requests per minute). Please wait 60 seconds."
        }, status=429)
    cache.set(rate_key, query_count + 1, timeout=60)
        
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

    if org_id:
        from core.models import Organization
        target_org = Organization.objects.filter(id=org_id).first()
        if target_org and target_org.get_active_seat_count() >= target_org.get_seat_quota():
            quota = target_org.get_seat_quota()
            plan_name = target_org.plan.upper()
            return JsonResponse({
                "detail": f"Organization seat quota reached ({quota} seat(s) on {plan_name} plan). Upgrade plan to add more members."
            }, status=403)
        
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
# Workspace Team & Invitation Management Endpoints
# -------------------------------------------------------------
@require_login
def organization_members_api(request):
    """
    GET: Returns active members, pending invitations, and seat quota details for the user's workspace.
    POST: Invites a new team member with role & permissions, validating against seat limits.
    """
    user_info = request.session.get('user')
    from core.models import Organization, OrganizationInvitation
    from django.utils import timezone
    import secrets

    org_id = user_info.get('organization_id')
    # If superadmin and no org_id in session, optionally accept ?org_id or pick first
    if not org_id and user_info.get('role') == 'admin':
        param_org = request.GET.get('org_id')
        if param_org:
            org = Organization.objects.filter(id=param_org).first()
        else:
            org = Organization.objects.first()
    else:
        org = Organization.objects.filter(id=org_id).first() if org_id else None

    if not org:
        return JsonResponse({"detail": "Workspace organization not found."}, status=404)

    can_manage = user_info.get('role') in ['admin', 'subadmin']

    if request.method == "GET":
        members = []
        for u in org.users.all().order_by('-created_at'):
            members.append({
                "username": u.username,
                "email": u.email,
                "full_name": u.full_name or u.username,
                "role": u.role,
                "job_title": u.job_title,
                "avatar_url": f"/api/user/avatar/{u.username}",
                "permissions": u.permissions,
                "is_verified": u.is_verified,
                "joined_at": u.created_at.strftime("%Y-%m-%d %H:%M") if u.created_at else "",
                "is_current_user": (u.username == user_info.get('username'))
            })

        invitations = []
        for inv in org.invitations.filter(status='pending', expires_at__gt=timezone.now()).order_by('-created_at'):
            invitations.append({
                "id": str(inv.id),
                "email": inv.email,
                "role": inv.role,
                "permissions": inv.permissions,
                "invited_by": inv.invited_by,
                "created_at": inv.created_at.strftime("%Y-%m-%d %H:%M"),
                "expires_at": inv.expires_at.strftime("%Y-%m-%d %H:%M"),
                "token": inv.token,
                "invite_url": request.build_absolute_uri(f"/invite/accept/{inv.token}")
            })

        seat_quota = org.get_seat_quota()
        active_seats = org.users.count()
        pending_seats = len(invitations)
        used_seats = active_seats + pending_seats

        return JsonResponse({
            "success": True,
            "organization": {
                "id": org.id,
                "name": org.name,
                "plan": org.plan,
                "seat_quota": seat_quota,
                "active_members_count": active_seats,
                "pending_invites_count": pending_seats,
                "used_seats": used_seats,
                "available_seats": max(0, seat_quota - used_seats) if seat_quota < 999999 else "Unlimited"
            },
            "members": members,
            "invitations": invitations,
            "can_manage": can_manage
        })

    elif request.method == "POST":
        if not can_manage:
            return JsonResponse({"detail": "Only workspace administrators can invite team members."}, status=403)

        try:
            data = json.loads(request.body)
        except Exception:
            return JsonResponse({"detail": "Invalid JSON payload."}, status=400)

        email = (data.get("email") or "").strip().lower()
        role = (data.get("role") or "operator").strip().lower()
        custom_permissions = data.get("permissions")

        if not email or "@" not in email:
            return JsonResponse({"detail": "A valid email address is required."}, status=400)

        if role not in ['operator', 'viewer', 'subadmin']:
            role = 'operator'

        # Subadmin cannot grant roles higher than operator or viewer unless superadmin
        if user_info.get('role') == 'subadmin' and role not in ['operator', 'viewer']:
            role = 'operator'

        # Enforce seat quota
        if org.get_active_seat_count() >= org.get_seat_quota():
            quota = org.get_seat_quota()
            plan_name = org.plan.upper()
            return JsonResponse({
                "detail": f"Seat quota reached ({quota} seat(s) on {plan_name} plan). Upgrade to Team Pro (10 seats) or Enterprise (unlimited) to invite more members."
            }, status=403)

        # Check if already an active member of this workspace
        if org.users.filter(email__iexact=email).exists():
            return JsonResponse({"detail": f"User with email '{email}' is already an active member of this workspace."}, status=400)

        # Check for existing active invite
        existing_invite = org.invitations.filter(email__iexact=email, status='pending', expires_at__gt=timezone.now()).first()
        if existing_invite:
            invite_url = request.build_absolute_uri(f"/invite/accept/{existing_invite.token}")
            return JsonResponse({
                "detail": f"An active invitation for '{email}' already exists.",
                "invite_url": invite_url
            }, status=400)

        # Resolve permissions
        if custom_permissions and isinstance(custom_permissions, dict):
            permissions = custom_permissions
        elif role == 'viewer':
            permissions = {"see": True, "create": False, "edit": False, "delete": False}
        elif role == 'operator':
            permissions = {"see": True, "create": True, "edit": True, "delete": False}
        else:
            permissions = {"see": True, "create": True, "edit": True, "delete": True}

        token = secrets.token_urlsafe(32)
        expires_at = timezone.now() + timezone.timedelta(days=7)

        invitation = OrganizationInvitation.objects.create(
            organization=org,
            email=email,
            role=role,
            permissions=permissions,
            token=token,
            invited_by=user_info.get('username'),
            expires_at=expires_at,
            status='pending'
        )

        invite_url = request.build_absolute_uri(f"/invite/accept/{token}")
        send_invitation_email(email, org.name, user_info.get('username'), role, invite_url)

        log_action(request, 'org.member_invited', 'organization', str(org.id), {
            'email': email,
            'role': role,
            'token': token
        })

        return JsonResponse({
            "success": True,
            "message": f"Invitation successfully sent to {email}",
            "invitation": {
                "id": str(invitation.id),
                "email": invitation.email,
                "role": invitation.role,
                "invite_url": invite_url,
                "expires_at": invitation.expires_at.strftime("%Y-%m-%d %H:%M")
            }
        })

    return HttpResponseNotAllowed(["GET", "POST"])


@require_login
def revoke_invitation_api(request, invite_id):
    """Cancels/revokes a pending workspace invitation."""
    if request.method != "DELETE":
        return HttpResponseNotAllowed(["DELETE"])

    user_info = request.session.get('user')
    if user_info.get('role') not in ['admin', 'subadmin']:
        return JsonResponse({"detail": "Only workspace administrators can revoke invitations."}, status=403)

    from core.models import OrganizationInvitation
    inv = OrganizationInvitation.objects.filter(id=invite_id).first()
    if not inv:
        return JsonResponse({"detail": "Invitation not found."}, status=404)

    if user_info.get('role') == 'subadmin' and inv.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized to revoke invitations for this workspace."}, status=403)

    inv.status = 'revoked'
    inv.save()

    log_action(request, 'org.invite_revoked', 'invitation', str(inv.id), {
        'email': inv.email,
        'organization': inv.organization.name
    })

    return JsonResponse({"success": True, "message": f"Invitation for {inv.email} revoked."})


@require_login
def remove_organization_member_api(request, username):
    """Removes a team member from the workspace."""
    if request.method != "DELETE":
        return HttpResponseNotAllowed(["DELETE"])

    user_info = request.session.get('user')
    if user_info.get('role') not in ['admin', 'subadmin']:
        return JsonResponse({"detail": "Only workspace administrators can remove team members."}, status=403)

    if username == user_info.get('username'):
        return JsonResponse({"detail": "You cannot remove yourself from the workspace."}, status=400)

    if username == 'admin':
        return JsonResponse({"detail": "Cannot remove the primary system administrator."}, status=400)

    from core.models import User
    member = User.objects.filter(username=username).first()
    if not member:
        return JsonResponse({"detail": "Member not found."}, status=404)

    if user_info.get('role') == 'subadmin':
        if member.organization_id != user_info.get('organization_id'):
            return JsonResponse({"detail": "Unauthorized to remove member from another workspace."}, status=403)
        if member.role == 'subadmin':
            return JsonResponse({"detail": "Cannot remove a fellow workspace administrator."}, status=400)

    org_name = member.organization.name if member.organization else "None"
    member.organization = None
    member.save()

    log_action(request, 'org.member_removed', 'user', username, {
        'organization': org_name
    })

    return JsonResponse({"success": True, "message": f"Member {username} removed from workspace."})


def accept_invitation_view(request, token):
    """
    GET: Displays the invitation accept page or error state.
    POST: Finalizes user account creation, links them to the organization, and logs them in.
    """
    from core.models import OrganizationInvitation, User
    from django.utils import timezone
    import re

    invitation = OrganizationInvitation.objects.filter(token=token).first()
    if not invitation:
        return render(request, 'core/accept_invite.html', {
            'error': 'Invalid invitation link. This link does not exist or was deleted.',
            'invitation': None
        })

    if invitation.status != 'pending' or invitation.expires_at <= timezone.now():
        msg = "This invitation has already been accepted." if invitation.status == 'accepted' else "This invitation has expired or was revoked."
        return render(request, 'core/accept_invite.html', {
            'error': msg,
            'invitation': None
        })

    role_label = 'Workspace Admin' if invitation.role == 'subadmin' else ('Data Engineer / Operator' if invitation.role == 'operator' else 'Read-Only Viewer')

    if request.method == "GET":
        return render(request, 'core/accept_invite.html', {
            'invitation': invitation,
            'organization': invitation.organization,
            'role_label': role_label,
            'error': None
        })

    elif request.method == "POST":
        # Handle both JSON fetch and traditional Form POST
        is_json = request.content_type == 'application/json' or 'application/json' in request.headers.get('Accept', '')
        if request.content_type == 'application/json':
            try:
                body = json.loads(request.body)
            except Exception:
                body = {}
            username = body.get('username', '').strip()
            password = body.get('password', '').strip()
            full_name = body.get('full_name', '').strip()
        else:
            username = request.POST.get('username', '').strip()
            password = request.POST.get('password', '').strip()
            full_name = request.POST.get('full_name', '').strip()

        def return_error(err_msg):
            if is_json:
                return JsonResponse({"detail": err_msg}, status=400)
            return render(request, 'core/accept_invite.html', {
                'invitation': invitation,
                'organization': invitation.organization,
                'role_label': role_label,
                'error': err_msg,
                'saved_username': username,
                'saved_fullname': full_name
            })

        if not username or len(username) < 3:
            return return_error("Username must be at least 3 characters long.")

        if not re.match(r'^[a-zA-Z0-9_\-]+$', username):
            return return_error("Username can only contain letters, numbers, underscores, and dashes.")

        if User.objects.filter(username=username).exists():
            return return_error(f"Username '{username}' is already taken. Please choose another username.")

        if not password or len(password) < 6:
            return return_error("Password must be at least 6 characters long.")

        # Check if user with this email already exists
        existing_email_user = User.objects.filter(email=invitation.email).first()
        if existing_email_user:
            existing_email_user.organization = invitation.organization
            existing_email_user.role = invitation.role
            existing_email_user.permissions = invitation.permissions
            existing_email_user.is_verified = True
            if full_name and not existing_email_user.full_name:
                existing_email_user.full_name = full_name
            existing_email_user.save()
            new_user = existing_email_user
        else:
            new_user = User.objects.create(
                username=username,
                email=invitation.email,
                password_hash=hash_password(password),
                full_name=full_name,
                role=invitation.role,
                permissions=invitation.permissions,
                organization=invitation.organization,
                is_verified=True
            )

        # Mark invitation accepted
        invitation.status = 'accepted'
        invitation.accepted_at = timezone.now()
        invitation.save()

        # Log audit action
        log_action(request, 'org.member_joined', 'user', new_user.username, {
            'organization': invitation.organization.name,
            'role': invitation.role,
            'email': invitation.email
        })

        # Set session to immediately log the user in
        request.session['user'] = {
            'username': new_user.username,
            'role': new_user.role,
            'permissions': new_user.permissions,
            'organization_id': new_user.organization_id,
            'organization_name': new_user.organization.name if new_user.organization else "Personal Org",
            'plan': new_user.organization.plan if new_user.organization else "free",
            'max_pipelines': new_user.organization.max_pipelines if new_user.organization else 5,
            'is_verified': True
        }

        if is_json:
            return JsonResponse({"success": True, "redirect_url": "/dashboard"})
        return redirect('dashboard')


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
    from core.models import Pipeline, SchemaSnapshot
    
    # Scope pipeline list to organization boundary
    if user_info.get('role') == 'admin':
        qs = Pipeline.objects.all().order_by('name')
    else:
        qs = Pipeline.objects.filter(organization_id=user_info.get('organization_id')).order_by('name')
        
    pipeline_list = []
    for p in qs:
        contract_path, _ = ensure_contract_and_snapshot_files(p)
        cols = []
        if contract_path and os.path.exists(contract_path):
            try:
                cfg = load_contract(contract_path)
                cols = cfg.get("columns", [])
            except Exception:
                pass
        if not cols and getattr(p, 'contract_yaml', None):
            try:
                import yaml
                cfg = yaml.safe_load(p.contract_yaml)
                if isinstance(cfg, dict):
                    cols = cfg.get("columns", [])
            except Exception:
                pass
        if not cols and getattr(p, 'schema_map', None):
            cols = p.schema_map.get("right") or p.schema_map.get("left") or []
        if not cols:
            snap = SchemaSnapshot.objects.filter(pipeline=p).order_by('-version').first()
            if snap and snap.schema_data:
                cols = snap.schema_data.get("columns", [])
                
        formatted_cols = []
        for c in cols:
            if isinstance(c, dict):
                formatted_cols.append({
                    "name": c.get("name", ""),
                    "type": str(c.get("type", "text")),
                    "nullable": c.get("nullable", True)
                })
            elif isinstance(c, str):
                formatted_cols.append({
                    "name": c,
                    "type": "text",
                    "nullable": True
                })

        pipeline_list.append({
            "id": p.id,
            "name": p.name,
            "table": p.table,
            "schema": p.schema,
            "db_type": p.db_type,
            "columns": formatted_cols
        })
        
    return render(request, 'core/sandbox.html', {
        "pipelines": pipeline_list,
        "pipelines_json": json.dumps(pipeline_list)
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
    contract_path, _ = ensure_contract_and_snapshot_files(p_obj)
    contract_cols = []
    if contract_path and os.path.exists(contract_path):
        try:
            cfg = load_contract(contract_path)
            contract_cols = cfg.get("columns", [])
        except Exception as e:
            logger.warning(f"Failed to load contract from {contract_path}: {e}")
            
    if not contract_cols and getattr(p_obj, 'contract_yaml', None):
        try:
            import yaml
            cfg = yaml.safe_load(p_obj.contract_yaml)
            if isinstance(cfg, dict):
                contract_cols = cfg.get("columns", [])
        except Exception:
            pass

    if not contract_cols and getattr(p_obj, 'schema_map', None):
        raw_map = p_obj.schema_map.get("right") or p_obj.schema_map.get("left") or []
        contract_cols = [
            {"name": c.get("name", ""), "type": str(c.get("type", "text")), "nullable": c.get("nullable", True)}
            for c in raw_map if isinstance(c, dict) and c.get("name")
        ]

    if not contract_cols:
        from core.models import SchemaSnapshot
        snap = SchemaSnapshot.objects.filter(pipeline=p_obj).order_by('-version').first()
        if snap and snap.schema_data:
            contract_cols = snap.schema_data.get("columns", [])
            
    if not contract_cols:
        return JsonResponse({"detail": "Active contract specifications not found on server."}, status=400)
        
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
        
    # Load contract design with multi-layer persistent fallback
    contract_path, _ = ensure_contract_and_snapshot_files(p_obj)
    columns = []
    if contract_path and os.path.exists(contract_path):
        try:
            cfg = load_contract(contract_path)
            columns = cfg.get("columns", [])
        except Exception as e:
            logger.warning(f"Failed to load contract from {contract_path}: {e}")

    if not columns and getattr(p_obj, 'contract_yaml', None):
        try:
            import yaml
            cfg = yaml.safe_load(p_obj.contract_yaml)
            if isinstance(cfg, dict):
                columns = cfg.get("columns", [])
        except Exception:
            pass

    if not columns and getattr(p_obj, 'schema_map', None):
        raw_map = p_obj.schema_map.get("right") or p_obj.schema_map.get("left") or []
        columns = [
            {"name": c.get("name", ""), "type": str(c.get("type", "text")), "nullable": c.get("nullable", True)}
            for c in raw_map if isinstance(c, dict) and c.get("name")
        ]

    if not columns:
        from core.models import SchemaSnapshot
        snap = SchemaSnapshot.objects.filter(pipeline=p_obj).order_by('-version').first()
        if snap and snap.schema_data:
            columns = snap.schema_data.get("columns", [])

    if not columns:
        return JsonResponse({"detail": "Active contract specifications not found on server."}, status=400)
    
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


# -------------------------------------------------------------
# Razorpay Automated Payment Gateway Endpoints
# -------------------------------------------------------------
@require_login
def razorpay_create_order_api(request):
    """
    Creates a Razorpay Order for automated instant checkout (UPI, Netbanking, Cards).
    Accepts JSON: { "plan": "pro" } or { "plan": "enterprise" }
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body) if request.body else {}
    except Exception:
        data = {}

    plan = (data.get("plan") or "pro").strip().lower()
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

    # Amount in INR Paise
    amount_paise = 399900 if plan == 'pro' else 1599900
    amount_display = "₹3,999" if plan == 'pro' else "₹15,999"

    key_id = getattr(settings, 'RAZORPAY_KEY_ID', 'rzp_test_placeholder')
    key_secret = getattr(settings, 'RAZORPAY_KEY_SECRET', '')
    is_live = key_secret and not key_id.startswith('rzp_test_placeholder')

    order_id = None
    if is_live:
        try:
            import base64
            import urllib.request
            auth_str = f"{key_id}:{key_secret}"
            b64_auth = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
            order_payload = {
                "amount": amount_paise,
                "currency": "INR",
                "receipt": f"sg_rcpt_{org.id}_{int(timezone.now().timestamp())}",
                "notes": {
                    "org_id": str(org.id),
                    "username": user.username,
                    "plan": plan
                }
            }
            req = urllib.request.Request(
                "https://api.razorpay.com/v1/orders",
                data=json.dumps(order_payload).encode('utf-8'),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Basic {b64_auth}"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as res:
                resp_data = json.loads(res.read().decode('utf-8'))
                order_id = resp_data.get("id")
        except Exception as e:
            logger.error(f"Failed to create live Razorpay order: {e}")
            order_id = None

    if not order_id:
        import uuid
        order_id = f"order_sim_{uuid.uuid4().hex[:14]}"

    return JsonResponse({
        "success": True,
        "key_id": key_id,
        "order_id": order_id,
        "amount": amount_paise,
        "amount_display": amount_display,
        "currency": "INR",
        "plan": plan,
        "name": "Schema Guard",
        "description": f"{plan.title()} Subscription (Automated Instant Activation)",
        "prefill": {
            "name": user.full_name or user.username,
            "email": user.email
        },
        "theme": {
            "color": "#8b5cf6" if plan == 'pro' else "#0ea5e9"
        }
    })


@require_login
def razorpay_verify_payment_api(request):
    """
    Verifies Razorpay payment signature and immediately upgrades the user's workspace.
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        data = json.loads(request.body) if request.body else {}
    except Exception:
        return JsonResponse({"detail": "Invalid JSON payload."}, status=400)

    razorpay_order_id = (data.get("razorpay_order_id") or "").strip()
    razorpay_payment_id = (data.get("razorpay_payment_id") or "").strip()
    razorpay_signature = (data.get("razorpay_signature") or "").strip()
    plan = (data.get("plan") or "pro").strip().lower()

    if not razorpay_payment_id:
        return JsonResponse({"detail": "Payment ID is required."}, status=400)

    key_id = getattr(settings, 'RAZORPAY_KEY_ID', 'rzp_test_placeholder')
    key_secret = getattr(settings, 'RAZORPAY_KEY_SECRET', '')
    is_live = key_secret and not key_id.startswith('rzp_test_placeholder')

    # Verify cryptographic HMAC-SHA256 signature if live secret configured
    if is_live and not razorpay_order_id.startswith("order_sim_"):
        import hmac
        import hashlib
        msg = f"{razorpay_order_id}|{razorpay_payment_id}".encode('utf-8')
        expected_sig = hmac.new(key_secret.encode('utf-8'), msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, razorpay_signature):
            return JsonResponse({"detail": "Payment signature verification failed."}, status=400)

    user_info = request.session.get('user', {})
    from core.models import User, Organization, PaymentTransaction
    from django.utils import timezone
    user = User.objects.filter(username=user_info.get('username')).first()
    if not user:
        return JsonResponse({"detail": "User not found."}, status=404)

    org = user.organization
    if not org:
        org = Organization.objects.create(name=f"{user.username}'s Workspace", plan='free', max_pipelines=5)
        user.organization = org
        user.save(update_fields=['organization'])

    quotas = getattr(settings, 'PLAN_QUOTAS', {})
    quota = quotas.get(plan, {}).get('max_pipelines', 50 if plan == 'pro' else 1000)

    # Immediately activate plan on organization
    org.plan = plan
    org.max_pipelines = quota
    org.subscription_status = 'active'
    org.save()

    # Synchronize active session so new permissions and badges reflect instantly
    user_info['plan'] = plan
    user_info['max_pipelines'] = quota
    user_info['organization_id'] = org.id
    user_info['organization_name'] = org.name
    request.session['user'] = user_info
    request.session.modified = True

    amount_display = "₹3,999" if plan == 'pro' else "₹15,999"

    # Record or update PaymentTransaction
    existing_tx = PaymentTransaction.objects.filter(transaction_id=razorpay_payment_id).first()
    if not existing_tx:
        PaymentTransaction.objects.create(
            transaction_id=razorpay_payment_id,
            organization=org,
            user=user,
            plan=plan,
            amount=amount_display,
            payment_method="RAZORPAY",
            status="approved",
            approved_at=timezone.now(),
            notes=f"Automated Razorpay Order {razorpay_order_id}"
        )

    log_action(request, 'billing.razorpay_payment', 'organization', str(org.id), {
        'plan': plan,
        'payment_id': razorpay_payment_id,
        'order_id': razorpay_order_id,
        'amount': amount_display
    })

    return JsonResponse({
        "success": True,
        "message": f"Payment verified! Your workspace has been upgraded to {plan.upper()} with {quota} pipelines.",
        "redirect_url": "/dashboard?upgraded=1"
    })


@csrf_exempt
def razorpay_webhook_api(request):
    """
    Handles Razorpay asynchronous webhook notifications (payment.captured, order.paid).
    """
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    body = request.body
    signature = request.META.get('HTTP_X_RAZORPAY_SIGNATURE', '')
    webhook_secret = getattr(settings, 'RAZORPAY_WEBHOOK_SECRET', '')

    if webhook_secret:
        import hmac
        import hashlib
        expected = hmac.new(webhook_secret.encode('utf-8'), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return JsonResponse({"detail": "Invalid webhook signature"}, status=400)

    try:
        event = json.loads(body.decode('utf-8'))
    except Exception:
        return JsonResponse({"detail": "Invalid JSON"}, status=400)

    event_type = event.get('event')
    if event_type in ['payment.captured', 'order.paid']:
        payload = event.get('payload', {}).get('payment', {}).get('entity', {})
        notes = payload.get('notes', {})
        org_id = notes.get('org_id')
        plan = notes.get('plan', 'pro')

        from core.models import Organization, PaymentTransaction
        from django.utils import timezone
        if org_id:
            org = Organization.objects.filter(id=org_id).first()
            if org:
                quotas = getattr(settings, 'PLAN_QUOTAS', {})
                org.plan = plan
                org.max_pipelines = quotas.get(plan, {}).get('max_pipelines', 50 if plan == 'pro' else 1000)
                org.subscription_status = 'active'
                org.save()

                payment_id = payload.get('id', 'pay_webhook')
                if not PaymentTransaction.objects.filter(transaction_id=payment_id).exists():
                    PaymentTransaction.objects.create(
                        transaction_id=payment_id,
                        organization=org,
                        plan=plan,
                        amount=f"₹{payload.get('amount', 0) / 100:.2f}",
                        payment_method="RAZORPAY_WEBHOOK",
                        status="approved",
                        approved_at=timezone.now()
                    )

    return JsonResponse({"status": "received", "event": event_type})


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


@require_login
def compliance_report_export_api(request):
    """
    Generates and exports a SOC 2 Type II and ISO/IEC 27001 Cryptographic Compliance Evidence Pack
    demonstrating data contract baseline locks, CI/CD breaking change gates, and schema drift controls.
    """
    import csv
    import hashlib
    import json
    import uuid
    from datetime import datetime, timezone
    from django.http import HttpResponse, JsonResponse
    from core.models import Pipeline, ContractVersion, GateValidationLog, WebhookDeliveryLog, AuditLog, Organization

    user_info = request.session.get('user', {})
    org_id = user_info.get('organization_id')
    role = user_info.get('role')

    if role == 'admin' and not org_id:
        pipelines_qs = Pipeline.objects.all()
        gate_qs = GateValidationLog.objects.all()
        webhook_qs = WebhookDeliveryLog.objects.all()
        audit_qs = AuditLog.objects.all()
        versions_qs = ContractVersion.objects.all()
        org_name = "Global Enterprise (All Organizations)"
    else:
        pipelines_qs = Pipeline.objects.filter(organization_id=org_id)
        pipeline_ids = list(pipelines_qs.values_list('id', flat=True))
        gate_qs = GateValidationLog.objects.filter(pipeline_id__in=pipeline_ids)
        webhook_qs = WebhookDeliveryLog.objects.filter(pipeline_id__in=pipeline_ids)
        audit_qs = AuditLog.objects.filter(organization_id=org_id)
        versions_qs = ContractVersion.objects.filter(pipeline_id__in=pipeline_ids)
        org = Organization.objects.filter(id=org_id).first()
        org_name = org.name if org else "Default Organization"

    total_pipelines = pipelines_qs.count()
    clean_pipelines = pipelines_qs.filter(status='Clean').count()
    drifted_pipelines = pipelines_qs.filter(status='Drifted').count()
    adherence_pct = round((clean_pipelines / total_pipelines * 100), 2) if total_pipelines > 0 else 100.0

    total_gate_checks = gate_qs.count()
    passed_gate_checks = gate_qs.filter(status='PASS').count()
    blocked_breaking = gate_qs.filter(status='FAIL').count()
    gate_pass_rate = round((passed_gate_checks / total_gate_checks * 100), 2) if total_gate_checks > 0 else 100.0

    total_webhooks = webhook_qs.count()
    successful_webhooks = webhook_qs.filter(success=True).count()
    webhook_success_rate = round((successful_webhooks / total_webhooks * 100), 2) if total_webhooks > 0 else 100.0

    total_versions = versions_qs.count()
    promotions_count = audit_qs.filter(action='pipeline.promoted').count()

    # Build contracts baseline registry
    baseline_registry = []
    for p in pipelines_qs.order_by('name'):
        latest_ver = versions_qs.filter(pipeline=p).order_by('-version_number').first()
        ver_num = latest_ver.version_number if latest_ver else 1
        col_count = len(p.schema_map) if isinstance(p.schema_map, dict) else 0
        baseline_registry.append({
            "pipeline_id": p.id,
            "name": p.name,
            "environment": getattr(p, 'environment', 'prod') or 'prod',
            "db_type": p.db_type,
            "schema": p.schema,
            "table": p.table,
            "lock_signature": p.lock_signature or "UNLOCKED",
            "active_version": ver_num,
            "columns_governed": col_count,
            "status": p.status,
            "last_checked": p.last_checked.strftime("%Y-%m-%d %H:%M:%S UTC") if p.last_checked else "Never",
            "integrity_seal": "VERIFIED_LOCKED" if p.lock_signature else "PENDING_LOCK"
        })

    # Recent change gate evaluations
    recent_gates = []
    for g in gate_qs.order_by('-checked_at')[:50]:
        recent_gates.append({
            "pipeline_id": g.pipeline_id,
            "commit_sha": g.commit_sha,
            "branch": g.branch,
            "status": g.status,
            "violations_count": g.violations_count,
            "checked_at": g.checked_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        })

    now_ts = datetime.now(timezone.utc).isoformat()
    report_id = f"SG-SOC2-{uuid.uuid4().hex[:12].upper()}"

    summary = {
        "report_id": report_id,
        "organization": org_name,
        "generated_at": now_ts,
        "auditor_frameworks": [
            "SOC 2 Type II: Trust Services Criteria CC6.1 (Logical Access), CC6.6 (Boundary Protection), CC6.8 (Unauthorized Changes), CC7.1 (Vulnerability Detection), CC7.2 (Security Monitoring)",
            "ISO/IEC 27001:2022: Control A.8.9 (Configuration Management), Control A.8.32 (Change Management)"
        ],
        "compliance_status": "COMPLIANT" if adherence_pct >= 80.0 else "REQUIRES_ATTENTION",
        "metrics": {
            "total_monitored_pipelines": total_pipelines,
            "clean_pipelines": clean_pipelines,
            "drifted_pipelines": drifted_pipelines,
            "contract_adherence_rate_pct": adherence_pct,
            "total_contract_baselines_locked": sum(1 for b in baseline_registry if b["lock_signature"] != "UNLOCKED"),
            "total_contract_revisions": total_versions,
            "multi_environment_promotions": promotions_count,
            "ci_cd_gate_evaluations": total_gate_checks,
            "ci_cd_blocked_breaking_changes": blocked_breaking,
            "ci_cd_gate_pass_rate_pct": gate_pass_rate,
            "webhook_notifications_dispatched": total_webhooks,
            "webhook_success_rate_pct": webhook_success_rate,
        }
    }

    seal_corpus = json.dumps({"summary": summary, "registry": baseline_registry}, sort_keys=True)
    cryptographic_seal = hashlib.sha256(seal_corpus.encode('utf-8')).hexdigest()
    summary["cryptographic_seal"] = f"sha256:{cryptographic_seal}"

    format_param = (request.GET.get('format') or 'json').lower().strip()

    if format_param == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="schema_guard_soc2_compliance_{now_ts[:10]}.csv"'
        writer = csv.writer(response)

        writer.writerow(["# SCHEMA GUARD SOC2 & ISO 27001 COMPLIANCE EVIDENCE PACK"])
        writer.writerow(["Report ID", report_id])
        writer.writerow(["Organization", org_name])
        writer.writerow(["Generated At", now_ts])
        writer.writerow(["Compliance Status", summary["compliance_status"]])
        writer.writerow(["Cryptographic Seal", summary["cryptographic_seal"]])
        writer.writerow([])

        writer.writerow(["# EXECUTIVE GOVERNANCE METRICS"])
        writer.writerow(["Metric", "Value"])
        for k, v in summary["metrics"].items():
            writer.writerow([k.replace("_", " ").title(), v])
        writer.writerow([])

        writer.writerow(["# DATA CONTRACT BASELINE REGISTRY & CRYPTOGRAPHIC HASHES"])
        writer.writerow(["Pipeline ID", "Name", "Environment", "Engine", "Table", "Columns Governed", "Lock Signature (SHA-256)", "Version", "Status", "Last Checked", "Integrity"])
        for b in baseline_registry:
            writer.writerow([
                b["pipeline_id"],
                b["name"],
                b["environment"].upper(),
                b["db_type"].upper(),
                b["table"],
                b["columns_governed"],
                b["lock_signature"],
                f"v{b['active_version']}",
                b["status"],
                b["last_checked"],
                b["integrity_seal"]
            ])
        writer.writerow([])

        writer.writerow(["# CI/CD CHANGE GATE RECENT EVALUATIONS (CC6.8 EVIDENCE)"])
        writer.writerow(["Pipeline ID", "Commit SHA", "Branch", "Status", "Violations Blocked", "Checked At"])
        for g in recent_gates:
            writer.writerow([
                g["pipeline_id"],
                g["commit_sha"],
                g["branch"],
                g["status"],
                g["violations_count"],
                g["checked_at"]
            ])

        return response

    report_data = {
        "compliance_summary": summary,
        "contract_baselines": baseline_registry,
        "cicd_gate_evidence": recent_gates,
    }
    response = JsonResponse(report_data, json_dumps_params={"indent": 2})
    response['Content-Disposition'] = f'attachment; filename="schema_guard_soc2_compliance_{now_ts[:10]}.json"'
    return response


@require_login
def list_drift_incidents_api(request):
    """
    List drift incidents with filtering by status, severity, or pipeline,
    plus overall MTTR / SLA governance metrics.
    """
    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    org_id = user_info.get('organization_id')
    role = user_info.get('role')

    from core.models import DriftIncident, Pipeline
    if role == 'admin' and not org_id:
        inc_qs = DriftIncident.objects.all()
    else:
        pipeline_ids = list(Pipeline.objects.filter(organization_id=org_id).values_list('id', flat=True))
        inc_qs = DriftIncident.objects.filter(pipeline_id__in=pipeline_ids)

    # Filters
    pipeline_filter = request.GET.get('pipeline_id')
    if pipeline_filter:
        inc_qs = inc_qs.filter(pipeline_id=pipeline_filter)

    status_filter = request.GET.get('status')
    if status_filter:
        inc_qs = inc_qs.filter(status=status_filter.upper())

    severity_filter = request.GET.get('severity')
    if severity_filter:
        inc_qs = inc_qs.filter(severity=severity_filter.upper())

    total_incidents = inc_qs.count()
    open_count = inc_qs.filter(status='OPEN').count()
    ack_count = inc_qs.filter(status='ACKNOWLEDGED').count()
    resolved_count = inc_qs.filter(status='RESOLVED').count()
    snoozed_count = inc_qs.filter(status='SNOOZED').count()

    resolved_with_mttr = inc_qs.filter(status='RESOLVED', mttr_seconds__isnull=False)
    total_mttr_sec = sum(resolved_with_mttr.values_list('mttr_seconds', flat=True))
    avg_mttr_min = round((total_mttr_sec / resolved_with_mttr.count()) / 60, 1) if resolved_with_mttr.exists() else 0.0

    items = []
    for inc in inc_qs.select_related('pipeline').order_by('-created_at')[:100]:
        items.append({
            "id": inc.id,
            "incident_number": inc.incident_number,
            "pipeline_id": inc.pipeline_id,
            "pipeline_name": inc.pipeline.name if inc.pipeline else "Unknown",
            "environment": getattr(inc.pipeline, "environment", "prod") if inc.pipeline else "prod",
            "status": inc.status,
            "severity": inc.severity,
            "title": inc.title,
            "violations": inc.violations,
            "violations_count": inc.violations_count,
            "acknowledged_by": inc.acknowledged_by,
            "acknowledged_at": inc.acknowledged_at.strftime("%Y-%m-%d %H:%M:%S UTC") if inc.acknowledged_at else None,
            "resolved_by": inc.resolved_by,
            "resolved_at": inc.resolved_at.strftime("%Y-%m-%d %H:%M:%S UTC") if inc.resolved_at else None,
            "resolution_notes": inc.resolution_notes,
            "auto_resolved": inc.auto_resolved,
            "snoozed_until": inc.snoozed_until.strftime("%Y-%m-%d %H:%M:%S UTC") if inc.snoozed_until else None,
            "mttr_seconds": inc.mttr_seconds,
            "mttr_minutes": round(inc.mttr_seconds / 60, 1) if inc.mttr_seconds else None,
            "created_at": inc.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        })

    return JsonResponse({
        "incidents": items,
        "metrics": {
            "total": total_incidents,
            "open": open_count,
            "acknowledged": ack_count,
            "resolved": resolved_count,
            "snoozed": snoozed_count,
            "avg_mttr_minutes": avg_mttr_min,
        }
    })


def _find_drift_incident(incident_id):
    from core.models import DriftIncident
    if str(incident_id).isdigit():
        return DriftIncident.objects.filter(models.Q(id=int(incident_id)) | models.Q(incident_number=str(incident_id))).select_related('pipeline').first()
    return DriftIncident.objects.filter(incident_number=str(incident_id)).select_related('pipeline').first()


@require_login
def get_drift_incident_detail_api(request, incident_id):
    if request.method != "GET":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    inc = _find_drift_incident(incident_id)
    if not inc:
        return JsonResponse({"detail": "Incident not found"}, status=404)

    if user_info.get('role') != 'admin' and inc.pipeline.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    return JsonResponse({
        "id": inc.id,
        "incident_number": inc.incident_number,
        "pipeline_id": inc.pipeline_id,
        "pipeline_name": inc.pipeline.name if inc.pipeline else "Unknown",
        "environment": getattr(inc.pipeline, "environment", "prod") if inc.pipeline else "prod",
        "status": inc.status,
        "severity": inc.severity,
        "title": inc.title,
        "violations": inc.violations,
        "violations_count": inc.violations_count,
        "acknowledged_by": inc.acknowledged_by,
        "acknowledged_at": inc.acknowledged_at.strftime("%Y-%m-%d %H:%M:%S UTC") if inc.acknowledged_at else None,
        "resolved_by": inc.resolved_by,
        "resolved_at": inc.resolved_at.strftime("%Y-%m-%d %H:%M:%S UTC") if inc.resolved_at else None,
        "resolution_notes": inc.resolution_notes,
        "auto_resolved": inc.auto_resolved,
        "snoozed_until": inc.snoozed_until.strftime("%Y-%m-%d %H:%M:%S UTC") if inc.snoozed_until else None,
        "mttr_seconds": inc.mttr_seconds,
        "created_at": inc.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
    })


@require_login
def acknowledge_drift_incident_api(request, incident_id):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    from core.models import AuditLog
    inc = _find_drift_incident(incident_id)
    if not inc:
        return JsonResponse({"detail": "Incident not found"}, status=404)

    if user_info.get('role') != 'admin' and inc.pipeline.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    actor = user_info.get('username') or 'user'
    now_dt = datetime.now(timezone.utc)
    inc.status = 'ACKNOWLEDGED'
    inc.acknowledged_by = actor
    inc.acknowledged_at = now_dt
    inc.save()

    AuditLog.objects.create(
        action='incident.acknowledge',
        actor=actor,
        target_type='drift_incident',
        target_id=inc.incident_number,
        organization=inc.pipeline.organization,
        details={
            "pipeline_id": inc.pipeline_id,
            "incident_number": inc.incident_number,
            "status": "ACKNOWLEDGED"
        }
    )

    return JsonResponse({
        "success": True,
        "message": f"Incident {inc.incident_number} acknowledged by {actor}.",
        "incident_number": inc.incident_number,
        "status": inc.status
    })


@require_login
def resolve_drift_incident_api(request, incident_id):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    from core.models import AuditLog
    inc = _find_drift_incident(incident_id)
    if not inc:
        return JsonResponse({"detail": "Incident not found"}, status=404)

    if user_info.get('role') != 'admin' and inc.pipeline.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    try:
        data = json.loads(request.body) if request.body else {}
    except Exception:
        data = {}

    actor = user_info.get('username') or 'user'
    now_dt = datetime.now(timezone.utc)
    notes = data.get('resolution_notes') or 'Resolved manually by engineer.'

    inc.status = 'RESOLVED'
    inc.resolved_by = actor
    inc.resolved_at = now_dt
    inc.resolution_notes = notes
    inc.auto_resolved = False
    inc.mttr_seconds = int((now_dt - inc.created_at).total_seconds()) if inc.created_at else 0
    inc.save()

    AuditLog.objects.create(
        action='incident.resolve',
        actor=actor,
        target_type='drift_incident',
        target_id=inc.incident_number,
        organization=inc.pipeline.organization,
        details={
            "pipeline_id": inc.pipeline_id,
            "incident_number": inc.incident_number,
            "resolution_notes": notes,
            "mttr_seconds": inc.mttr_seconds
        }
    )

    return JsonResponse({
        "success": True,
        "message": f"Incident {inc.incident_number} resolved.",
        "incident_number": inc.incident_number,
        "mttr_seconds": inc.mttr_seconds,
        "status": inc.status
    })


@require_login
def snooze_drift_incident_api(request, incident_id):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    user_info = request.session.get('user', {})
    from core.models import AuditLog
    inc = _find_drift_incident(incident_id)
    if not inc:
        return JsonResponse({"detail": "Incident not found"}, status=404)

    if user_info.get('role') != 'admin' and inc.pipeline.organization_id != user_info.get('organization_id'):
        return JsonResponse({"detail": "Unauthorized"}, status=403)

    try:
        data = json.loads(request.body) if request.body else {}
    except Exception:
        data = {}

    hours = int(data.get('hours', 4))
    actor = user_info.get('username') or 'user'
    now_dt = datetime.now(timezone.utc)
    snooze_until = now_dt + timedelta(hours=hours)

    inc.status = 'SNOOZED'
    inc.snoozed_until = snooze_until
    inc.save()

    AuditLog.objects.create(
        action='incident.snooze',
        actor=actor,
        target_type='drift_incident',
        target_id=inc.incident_number,
        organization=inc.pipeline.organization,
        details={
            "pipeline_id": inc.pipeline_id,
            "incident_number": inc.incident_number,
            "snoozed_until": snooze_until.isoformat(),
            "hours": hours
        }
    )

    return JsonResponse({
        "success": True,
        "message": f"Incident {inc.incident_number} snoozed for {hours} hour(s).",
        "incident_number": inc.incident_number,
        "snoozed_until": snooze_until.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "status": inc.status
    })


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





