import logging
from datetime import datetime, timezone
from django.utils import timezone as dj_timezone
from schema_guard_django.core.models import User, Pipeline, Organization

logger = logging.getLogger("schema_guard_db_impl")

def init_db():
    try:
        from django.db import connection
        if 'core_user' in connection.introspection.table_names():
            # Check or create default admin
            admin_user = User.objects.filter(username='admin').first()
            if not admin_user:
                # Import views.hash_password dynamically to avoid circular import issues
                from schema_guard_django.core.views import hash_password
                User.objects.create(
                    username='admin',
                    email='anusolanki2645@gmail.com',  # Super Admin email from .env
                    password_hash=hash_password('Anil@2645'),
                    role='admin',
                    permissions={"see": True, "create": True, "edit": True, "delete": True},
                    is_verified=True
                )
                logger.info("Default Super Admin 'admin' successfully seeded.")
    except Exception as e:
        logger.warning(f"Database initialization deferred (tables may not exist yet): {e}")

def serialize_user(u):
    if not u:
        return None
    return {
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "permissions": u.permissions,
        "organization_id": u.organization_id,
        "organization_name": u.organization.name if u.organization else None,
        "is_verified": u.is_verified,
        "created": u.created_at.strftime("%Y-%m-%d %H:%M:%S")
    }

def serialize_pipeline(p):
    if not p:
        return None
    
    last_checked_str = ""
    if p.last_checked:
        # Check if last_checked is naive or aware
        if p.last_checked.tzinfo is not None:
            last_checked_str = p.last_checked.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        else:
            last_checked_str = p.last_checked.strftime("%Y-%m-%d %H:%M:%S")

    return {
        "id": p.id,
        "name": p.name,
        "dbType": p.db_type,
        "connStr": p.conn_str,
        "schema": p.schema,
        "table": p.table,
        "cron": p.cron,
        "cronText": p.cron_text,
        "alerts": p.alerts,
        "status": p.status,
        "lastChecked": last_checked_str,
        "lockSignature": p.lock_signature,
        "schemaMap": p.schema_map,
        "logs": p.logs,
        "complianceHistory": p.compliance_history,
        "organization_id": p.organization_id,
        "organization_name": p.organization.name if p.organization else None
    }

def get_user(username):
    u = User.objects.filter(username=username).first()
    return serialize_user(u)

def count_users():
    return User.objects.count()

def create_user(username, email, password_hash, role, permissions, organization_id=None, is_verified=False, verification_code=None):
    org = None
    if organization_id:
        org = Organization.objects.filter(id=organization_id).first()
    u = User.objects.create(
        username=username,
        email=email,
        password_hash=password_hash,
        role=role,
        permissions=permissions,
        organization=org,
        is_verified=is_verified,
        verification_code=verification_code
    )
    return serialize_user(u)

def get_user_with_hash(username):
    u = User.objects.filter(username=username).first()
    if not u:
        return None
    data = serialize_user(u)
    data["password_hash"] = u.password_hash
    return data

def get_all_pipelines():
    return [serialize_pipeline(p) for p in Pipeline.objects.all().order_by('-created_at')]

# Helper to custom-sort or get pipelines
class PipelineQuerySetHelper:
    @staticmethod
    def get_pipelines_for_org(org_id=None, is_admin=False):
        if is_admin:
            qs = Pipeline.objects.all().order_by('-created_at')
        else:
            qs = Pipeline.objects.filter(organization_id=org_id).order_by('-created_at')
        return [serialize_pipeline(p) for p in qs]

def pipeline_exists(pipe_id):
    return Pipeline.objects.filter(id=pipe_id).exists()

def create_pipeline(p):
    # p is a dict
    org = None
    org_id = p.get("organization_id")
    if org_id:
        org = Organization.objects.filter(id=org_id).first()
        
    last_checked_val = None
    if p.get("lastChecked"):
        try:
            last_checked_val = datetime.strptime(p["lastChecked"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            last_checked_val = dj_timezone.now()

    pipe = Pipeline.objects.create(
        id=p["id"],
        name=p["name"],
        db_type=p["dbType"],
        conn_str=p["connStr"],
        schema=p["schema"],
        table=p["table"],
        cron=p.get("cron", "0 0 * * *"),
        cron_text=p.get("cronText", "Daily preset"),
        alerts=p.get("alerts", {}),
        status=p.get("status", "Clean"),
        last_checked=last_checked_val,
        lock_signature=p.get("lockSignature"),
        schema_map=p.get("schemaMap", {"left": [], "right": []}),
        logs=p.get("logs", []),
        compliance_history=p.get("complianceHistory", []),
        organization=org
    )
    return serialize_pipeline(pipe)

def get_pipeline(id):
    p = Pipeline.objects.filter(id=id).first()
    return serialize_pipeline(p)

def update_pipeline(id, updates):
    pipe = Pipeline.objects.filter(id=id).first()
    if not pipe:
        return None
    
    # Map updates keys (camelCase or snake_case)
    if "connStr" in updates:
        pipe.conn_str = updates["connStr"]
    if "cron" in updates:
        pipe.cron = updates["cron"]
    if "cronText" in updates:
        pipe.cron_text = updates["cronText"]
    if "alerts" in updates:
        pipe.alerts = updates["alerts"]
    if "status" in updates:
        pipe.status = updates["status"]
    if "lastChecked" in updates:
        try:
            pipe.last_checked = datetime.strptime(updates["lastChecked"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            pipe.last_checked = dj_timezone.now()
    if "lockSignature" in updates:
        pipe.lock_signature = updates["lockSignature"]
    if "schemaMap" in updates:
        pipe.schema_map = updates["schemaMap"]
    if "logs" in updates:
        pipe.logs = updates["logs"]
    if "complianceHistory" in updates:
        pipe.compliance_history = updates["complianceHistory"]
        
    pipe.save()
    return serialize_pipeline(pipe)

def delete_pipeline(id):
    deleted, _ = Pipeline.objects.filter(id=id).delete()
    return deleted > 0

def get_all_users():
    return [serialize_user(u) for u in User.objects.all().order_by('-created_at')]

def update_user_role(username, role, permissions):
    u = User.objects.filter(username=username).first()
    if not u:
        return None
    u.role = role
    u.permissions = permissions
    u.save()
    return serialize_user(u)

def delete_user(username):
    deleted, _ = User.objects.filter(username=username).delete()
    return deleted > 0
