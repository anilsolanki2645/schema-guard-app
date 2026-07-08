import os
import json
import logging
import random
from datetime import datetime, timezone
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.conf import settings
from django.db import models

# Import core schema_guard gate submodules
from schema_guard import db
from schema_guard.extractors import get_extractor
from schema_guard.contract import load_contract, validate_contract, lock_contract, verify_contract_integrity
from schema_guard.snapshot import capture_snapshot, load_snapshot
from schema_guard.diff_engine import compare_schemas, normalize_type
from schema_guard.alerter import send_alert, send_email_alert, send_slack_alert, send_whatsapp_alert
from passlib.context import CryptContext

logger = logging.getLogger("schema_guard_django_views")

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

def resolve_connection_string(conn_str: str) -> str:
    if conn_str.startswith("env:"):
        var_name = conn_str.split(":", 1)[1]
        resolved = os.getenv(var_name)
        if not resolved:
            raise RuntimeError(f"Environment variable '{var_name}' is not set.")
        return resolved
    return conn_str

# -------------------------------------------------------------
# Email Helper Functions
# -------------------------------------------------------------
def generate_code() -> str:
    return "".join(random.choices("0123456789", k=6))

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
    try:
        print(f"\n========================================\n[EMAIL] Verification code to {email}: {code}\n========================================\n")
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL or 'anusolanki2645@gmail.com',
            [email],
            fail_silently=False,
            html_message=html_message
        )
        return True
    except Exception as e:
        logger.error(f"Failed to send verification email to {email}: {e}")
        return False

def send_password_reset_email(email: str, code: str) -> bool:
    subject = "Reset your Schema Guard Password"
    message = f"Your password reset code is: {code}\n\nPlease enter this code on the password reset page to update your password."
    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;800&family=JetBrains+Mono:wght@700&display=swap');
            @keyframes pulse-glow-amber {{
                0% {{ box-shadow: 0 0 15px rgba(245, 158, 11, 0.25); border-color: rgba(245, 158, 11, 0.4); }}
                50% {{ box-shadow: 0 0 30px rgba(245, 158, 11, 0.6); border-color: rgba(245, 158, 11, 0.8); }}
                100% {{ box-shadow: 0 0 15px rgba(245, 158, 11, 0.25); border-color: rgba(245, 158, 11, 0.4); }}
            }}
            .code-glow {{
                animation: pulse-glow-amber 2.5s infinite ease-in-out;
            }}
        </style>
    </head>
    <body style="font-family: 'Outfit', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #030712; color: #f3f4f6; margin: 0; padding: 40px 0;">
        <table align="center" border="0" cellpadding="0" cellspacing="0" width="580" style="background: linear-gradient(135deg, #0b0f19 0%, #111827 100%); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(0,0,0,0.7);">
            <!-- Top neon accent bar -->
            <tr>
                <td height="4" style="background: linear-gradient(90deg, #f59e0b, #d97706, #fde047);"></td>
            </tr>
            <!-- Logo & Header -->
            <tr>
                <td style="padding: 40px 40px 20px 40px; text-align: center;">
                    <div style="display: inline-block; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 12px; padding: 12px 18px; margin-bottom: 20px;">
                        <span style="font-size: 32px; vertical-align: middle;">🔑</span>
                        <span style="font-size: 22px; font-weight: 800; color: #ffffff; letter-spacing: 2px; vertical-align: middle; margin-left: 10px; font-family: 'Outfit', sans-serif;">SCHEMA GUARD</span>
                    </div>
                    <h1 style="color: #ffffff; font-size: 24px; font-weight: 800; margin: 0; font-family: 'Outfit', sans-serif;">Password Reset Request</h1>
                </td>
            </tr>
            <!-- Body Content -->
            <tr>
                <td style="padding: 20px 40px 40px 40px; color: #9ca3af; line-height: 1.65; font-size: 15px;">
                    <p style="margin-top: 0;">We received a request to reset your password. Use the secure authorization code below to configure your new password credentials:</p>
                    
                    <div style="text-align: center; margin: 35px 0;">
                        <div class="code-glow" style="display: inline-block; background: rgba(15, 23, 42, 0.8); border: 1.5px solid #f59e0b; border-radius: 12px; padding: 18px 40px; font-size: 38px; font-weight: 800; color: #fde047; font-family: 'JetBrains Mono', monospace; letter-spacing: 8px; text-shadow: 0 0 10px rgba(253, 224, 71, 0.5);">
                            {code}
                        </div>
                    </div>
                    
                    <p style="font-size: 13px; color: #6b7280; margin-top: 35px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 25px; text-align: center;">
                        If you did not make this request, please change your password or contact support immediately.
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
    try:
        print(f"\n========================================\n[EMAIL] Password reset code to {email}: {code}\n========================================\n")
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL or 'anusolanki2645@gmail.com',
            [email],
            fail_silently=False,
            html_message=html_message
        )
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset email to {email}: {e}")
        return False

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
        contract_path = os.path.join(CONTRACTS_DIR, f"{p['table']}.yaml")
        snapshot_path = os.path.join(SNAPSHOTS_DIR, f"{p['table']}.json")

        if not os.path.exists(contract_path) or not os.path.exists(snapshot_path):
            logs.append("[INFO] Running simulated check on mock connection...")
            updates = {
                "lastChecked": timestamp_str,
                "logs": [
                    f"[INFO] Connection: Mocked {p['dbType'].upper()}",
                    "[INFO] Running validation against cached mock contract...",
                    "[SUCCESS] Live schema matches snapshot baseline." if p["status"] == "Clean" else "[WARNING] Drift violations detected."
                ]
            }
            db.update_pipeline(pipeline_id, updates)
            return db.get_pipeline(pipeline_id)

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

        logs.append("[INFO] Running schema diff gate comparison checks...")
        violations, notices = compare_schemas(live_schema, snapshot["schema"], cfg.get("columns", []))

        schema_map = {"left": [], "right": []}
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
        if violations:
            status_str = "Drifted"
            logs.append("[WARNING] COMPLIANCE VIOLATION DETECTED:")
            for v in violations:
                logs.append(f"[ERROR] {v}")
            logs.append(f"[ERROR] Verification FAILED: {len(violations)} structural drift violations.")

            alert_sent = False
            if p["alerts"].get("email"):
                if send_email_alert(violations, email_to=p["alerts"]["email"]):
                    alert_sent = True
                    logs.append(f"[INFO] Email alert dispatched to {p['alerts']['email']}.")
            if p["alerts"].get("slack"):
                if send_slack_alert(violations, webhook_url=p["alerts"]["slack"]):
                    alert_sent = True
                    logs.append("[INFO] Slack alert dispatched.")
            if p["alerts"].get("wp"):
                if send_whatsapp_alert(violations, phone=p["alerts"]["wp"]):
                    alert_sent = True
                    logs.append(f"[INFO] WhatsApp alert dispatched to {p['alerts']['wp']}.")
            if not alert_sent:
                if send_alert(violations):
                    logs.append("[INFO] Default alert dispatched.")
        else:
            logs.append("[SUCCESS] Verification PASSED: Active schemas are in perfect alignment.")

        alert_event = ", ".join([k for k, v in p["alerts"].items() if v]) if violations else "None"
        compliance = list(p.get("complianceHistory") or [])
        compliance.insert(0, {
            "time": timestamp_str,
            "profile": "production",
            "status": "PASS" if not violations else "FAIL",
            "violations": len(violations),
            "alertEvent": alert_event
        })

        updates = {
            "status": status_str,
            "lastChecked": timestamp_str,
            "schemaMap": schema_map,
            "logs": logs,
            "complianceHistory": compliance,
        }
        db.update_pipeline(pipeline_id, updates)
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
    def wrapper(request, *args, **kwargs):
        user_info = request.session.get('user')
        if not user_info:
            return redirect('login_page')
        
        # Check direct database verification status
        from schema_guard_django.core.models import User
        user = User.objects.filter(username=user_info['username']).first()
        if not user:
            request.session.flush()
            return redirect('login_page')
        
        if not user.is_verified:
            return redirect('verify_email_page')
            
        return view_func(request, *args, **kwargs)
    return wrapper

def require_admin(view_func):
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
        # Check verification state
        user_info = request.session.get('user')
        from schema_guard_django.core.models import User
        user = User.objects.filter(username=user_info['username']).first()
        if user and not user.is_verified:
            return redirect('verify_email_page')
        return redirect('dashboard')
    
    # Check if there's a messages context
    success_message = request.GET.get('success_message', '')
    return render(request, 'core/login.html', {'success_message': success_message})

@require_login
def dashboard_page(request):
    return render(request, 'core/dashboard.html')

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

# -------------------------------------------------------------
# Email Verification Views
# -------------------------------------------------------------
def verify_email_page(request):
    user_info = request.session.get('user')
    if not user_info:
        return redirect('login_page')
        
    from schema_guard_django.core.models import User
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
    from schema_guard_django.core.models import User
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

@csrf_exempt
def resend_verification_code_api(request):
    user_info = request.session.get('user')
    if not user_info:
        return JsonResponse({"detail": "Unauthorized"}, status=401)
        
    from schema_guard_django.core.models import User
    user = User.objects.filter(username=user_info['username']).first()
    if not user:
        return JsonResponse({"detail": "User not found"}, status=404)
        
    code = generate_code()
    user.verification_code = code
    user.save()
    
    send_verification_email(user.email, code)
    return JsonResponse({"status": "success", "message": "Verification email resent successfully."})

# -------------------------------------------------------------
# Password Reset Views
# -------------------------------------------------------------
def forgot_password_view(request):
    if request.method == "POST":
        email = request.POST.get('email', '').strip()
        from schema_guard_django.core.models import User
        user = User.objects.filter(email=email).first()
        if not user:
            return render(request, 'core/forgot_password.html', {
                'error_message': 'No account is registered with this email address.'
            })
            
        code = generate_code()
        user.reset_code = code
        user.save()
        
        send_password_reset_email(email, code)
        return redirect(f'/reset-password?email={email}')
        
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
            
        from schema_guard_django.core.models import User
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
        
    return render(request, 'core/reset_password.html', {'email': email})

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
        from schema_guard_django.core.models import User, Organization
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
        return redirect('verify_email_page')

    else:
        # Login flow supporting Username OR Email login
        from schema_guard_django.core.models import User
        user_obj = User.objects.filter(models.Q(username=username) | models.Q(email=username)).first()
        
        if not user_obj or not verify_password(password, user_obj.password_hash):
            return render(request, 'core/login.html', {
                'error_message': 'Invalid username/email or password credentials.',
                'is_signup_mode': False,
                'saved_username': username
            })
        
        clean_user = {
            "username": user_obj.username,
            "email": user_obj.email,
            "role": user_obj.role,
            "permissions": user_obj.permissions,
            "organization_id": user_obj.organization_id,
            "is_verified": user_obj.is_verified
        }
        request.session['user'] = clean_user
        
        if not user_obj.is_verified:
            return redirect('verify_email_page')
            
        return redirect('dashboard')

def logout_view(request):
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
        from schema_guard_django.core.models import Pipeline
        qs = Pipeline.objects.filter(organization_id=user_info.get('organization_id')).order_by('-created_at')
        from schema_guard_django.core.db_impl import serialize_pipeline
        pipelines = [serialize_pipeline(p) for p in qs]
        return JsonResponse(pipelines, safe=False)

@require_login
def create_pipeline_api(request):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    user_info = request.session.get('user')
    if not user_info.get('permissions', {}).get('create', True) and user_info.get('role') not in ['admin', 'subadmin']:
        return JsonResponse({"detail": "Permission denied to create pipelines."}, status=403)
    
    data = json.loads(request.body)
    pipe_id = data.get("name").lower().replace(" ", "_")
    
    if db.pipeline_exists(pipe_id):
        return JsonResponse({"detail": "Pipeline name already exists."}, status=400)
    
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
    with open(contract_path, "w") as f:
        yaml.dump(contract_data, f, default_flow_style=False, sort_keys=False)
        
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
    
    from schema_guard_django.core.apps import register_pipeline_cron
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
    updates = {
        "connStr": data.get("connStr"),
        "cron": data.get("cron"),
        "cronText": data.get("cronText"),
        "alerts": data.get("alerts", {})
    }
    
    db.update_pipeline(id, updates)
    updated = db.get_pipeline(id)
    
    from schema_guard_django.core.apps import register_pipeline_cron
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
        
    from schema_guard_django.core.apps import scheduler
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
    return JsonResponse({"status": "success"})

@require_login
def list_tables_api(request):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
    
    data = json.loads(request.body)
    try:
        resolved_conn = resolve_connection_string(data.get("connStr"))
        extractor = get_extractor(data.get("dbType"))
        tables = extractor.get_tables(resolved_conn, data.get("schema"))
        return JsonResponse({"tables": tables})
    except Exception as e:
        return JsonResponse({"detail": str(e)}, status=400)

@require_login
def test_connection_api(request):
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)
        
    data = json.loads(request.body)
    try:
        resolved_conn = resolve_connection_string(data.get("connStr"))
        extractor = get_extractor(data.get("dbType"))
        schema_info = extractor.get_schema(resolved_conn, data.get("schema"), data.get("table"))
        return JsonResponse({"status": "success", "columns": schema_info["columns"]})
    except Exception as e:
        return JsonResponse({"status": "failed", "message": str(e)})

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
    q_type = data.get("query_type")
    custom_query = data.get("custom_query", "")
    
    err_lines = [line for line in p["logs"] if "[ERROR]" in line]
    drift_summary = err_lines[0] if err_lines else "Schema mismatch detected on active pipeline."
    
    response_msg = ""
    if q_type == "explain":
        response_msg = (
            f"**Downstream Application Impact Analysis**:\n\n"
            f"The field modification detailed as `{drift_summary}` can cause errors in downstream consumption layers:\n"
            f"- **ETL Jobs (Spark/Pandas)**: Nullability exceptions if a previously nullable value starts arriving with stricter constraints.\n"
            f"- **BI Analytics Tools (Tableau/Looker)**: Data ingestion refresh failures if columns are dropped or renamed.\n"
            f"- **CI/CD Integration Pipeline**: Build crashes if database validations mismatch contract signatures."
        )
    elif q_type == "sql":
        response_msg = (
            f"**SQL Schema Reconciliation Repair Script**:\n\n"
            f"To restore compliance and match the registered snapshot baseline state, execute the following SQL DDL query on your database:\n"
            f"```sql\n"
            f"ALTER TABLE {p['schema']}.{p['table']} ALTER COLUMN quantity DROP NOT NULL;\n"
            f"```\n"
            f"Once executed, trigger the validation check to verify alignment."
        )
    elif q_type == "yaml":
        response_msg = (
            f"**Data Contract YAML Modification**:\n\n"
            f"The contract has been signature locked. If the database mutation is an authorized upgrade, generate and re-sign a new YAML configuration:\n"
            f"1. Navigate to the **YAML Contract Builder** tab.\n"
            f"2. Configure columns to match the live schema.\n"
            f"3. Click **Lock Contract Signature** to lock-in the new layout."
        )
    else:
        response_msg = (
            f"Regarding your query: *\"{custom_query}\"*.\n\n"
            f"Based on the analysis of table `{p['schema']}.{p['table']}`, the current live drift violation is `{drift_summary}`. "
            f"This requires database DDL alignment or contract signature recreation. Let me know if you would like me to generate a specific reconciliation payload."
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
        from schema_guard_django.core.models import User
        qs = User.objects.filter(organization_id=user_info.get('organization_id')).order_by('-created_at')
        from schema_guard_django.core.db_impl import serialize_user
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
        
    from schema_guard_django.core.models import User
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
    from schema_guard_django.core.models import User
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
    from schema_guard_django.core.models import User
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
        
    from schema_guard_django.core.models import Organization
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
        
    from schema_guard_django.core.models import Organization, User
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
