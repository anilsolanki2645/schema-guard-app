"""
Audit logging utility for Schema Guard.
Provides helpers to create immutable audit trail entries for all user actions.
"""
import logging
from core.models import AuditLog, Organization

logger = logging.getLogger("core_audit")


def get_client_ip(request):
    """Extract client IP address from request, handling proxied requests."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def log_action(request, action, target_type='', target_id='', details=None):
    """
    Record an audit trail entry.
    
    Args:
        request: Django HttpRequest (or None for system-initiated actions)
        action: Action identifier from AuditLog.ACTION_CHOICES
        target_type: Type of resource affected (e.g., 'pipeline', 'user')
        target_id: Identifier of the affected resource
        details: Optional dict with additional context
    """
    if details is None:
        details = {}
    
    actor = 'system'
    org_id = None
    ip_address = None
    
    if request:
        user_info = getattr(request, 'session', {}).get('user', {}) if request else {}
        if user_info:
            actor = user_info.get('username', 'unknown')
            org_id = user_info.get('organization_id')
        ip_address = get_client_ip(request)
    
    org = None
    if org_id:
        org = Organization.objects.filter(id=org_id).first()
    
    try:
        AuditLog.objects.create(
            action=action,
            actor=actor,
            target_type=target_type,
            target_id=str(target_id),
            details=details,
            organization=org,
            ip_address=ip_address,
        )
    except Exception as e:
        logger.error(f"Failed to write audit log: {action} by {actor} -> {e}")


def log_system_action(action, target_type='', target_id='', details=None):
    """Record an audit trail entry for system-initiated actions (no request context)."""
    log_action(None, action, target_type, target_id, details)
