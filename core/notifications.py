import hashlib
import hmac
import ipaddress
import json
import logging
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse
from django.conf import settings

logger = logging.getLogger(__name__)


def validate_webhook_url(url: str, allow_internal: bool = False) -> tuple[bool, str]:
    """Validates URL against SSRF and private network attacks."""
    if not url or not isinstance(url, str):
        return False, "Webhook URL cannot be empty."

    parsed = urlparse(url.strip())
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        return False, f"Invalid URL scheme or missing host in '{url}'."

    host = (parsed.hostname or '').lower()
    blocked_hosts = {'localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254', 'metadata.google.internal'}

    if not allow_internal:
        if host in blocked_hosts or host.endswith('.internal') or host.endswith('.local'):
            return False, f"SSRF protection: Webhook target host '{host}' is an internal network address."
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False, f"SSRF protection: Webhook target IP '{host}' is private/loopback."
        except ValueError:
            pass

    return True, "Valid"


def send_rich_slack_alert(
    violations: list,
    pipeline_name: str = "Database Pipeline",
    table_name: str = "",
    db_type: str = "DATABASE",
    webhook_url: str = None,
    app_url: str = "https://schema-guard-app.onrender.com",
    is_test: bool = False
) -> tuple[bool, str]:
    """
    Dispatches a high-fidelity Slack Block Kit notification with drift severity colors and 1-click action buttons.
    """
    if not webhook_url:
        return False, "Slack Webhook URL is missing."

    is_valid, reason = validate_webhook_url(webhook_url)
    if not is_valid:
        return False, reason

    header_title = "🧪 [TEST] Schema Guard Slack Alert" if is_test else "🚨 Schema Drift Mutation Detected"
    status_text = "TEST PREVIEW" if is_test else f"DRIFTED ({len(violations)} Violations)"

    # Format violations list with colored risk icons
    bullet_items = []
    for v in violations:
        v_str = str(v)
        if "DROPPED" in v_str.upper() or "NOT FOUND" in v_str.upper() or "MISSING" in v_str.upper():
            bullet_items.append(f"• 🔴 `{v_str}`")
        elif "TYPE" in v_str.upper() or "MISMATCH" in v_str.upper():
            bullet_items.append(f"• ⚠️ `{v_str}`")
        else:
            bullet_items.append(f"• 🟡 `{v_str}`")

    formatted_violations = "\n".join(bullet_items) if bullet_items else "• ℹ️ All checks nominal."

    payload = {
        "text": f"[{pipeline_name}] Schema Drift Alert: {len(violations)} structural changes detected",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": header_title,
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Pipeline:*\n`{pipeline_name}`"},
                    {"type": "mrkdwn", "text": f"*Target Table:*\n`{table_name or 'Production Catalog'}`"},
                    {"type": "mrkdwn", "text": f"*Database Engine:*\n`{db_type.upper()}`"},
                    {"type": "mrkdwn", "text": f"*Audit Status:*\n*{status_text}*"}
                ]
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Contract Structural Violations:*\n{formatted_violations}"
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🔍 View in Dashboard", "emoji": True},
                        "style": "primary",
                        "url": f"{app_url}/dashboard"
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🧪 DDL Shadow Sandbox", "emoji": True},
                        "url": f"{app_url}/sandbox"
                    }
                ]
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"🛡️ *Schema Guard Continuous Policy Engine* • Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
                    }
                ]
            }
        ]
    }

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "SchemaGuard-Slack-Dispatcher/1.0"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=8) as res:
            if res.status in (200, 201, 202, 204):
                return True, "Slack alert delivered successfully."
            return False, f"Slack responded with HTTP {res.status}"
    except Exception as e:
        logger.error(f"Failed to dispatch Slack alert to {webhook_url}: {e}")
        return False, str(e)


def send_rich_teams_alert(
    violations: list,
    pipeline_name: str = "Database Pipeline",
    table_name: str = "",
    db_type: str = "DATABASE",
    webhook_url: str = None,
    app_url: str = "https://schema-guard-app.onrender.com",
    is_test: bool = False
) -> tuple[bool, str]:
    """
    Dispatches a Microsoft Teams MessageCard / Adaptive Card with schema drift facts and action links.
    """
    if not webhook_url:
        return False, "Microsoft Teams Webhook URL is missing."

    is_valid, reason = validate_webhook_url(webhook_url)
    if not is_valid:
        return False, reason

    theme_color = "0ea5e9" if is_test else "ef4444"
    title_text = "🧪 [TEST] Schema Guard Teams Alert" if is_test else "🚨 Schema Drift Mutation Detected"

    bullet_lines = []
    for v in violations:
        v_str = str(v)
        if "DROPPED" in v_str.upper() or "NOT FOUND" in v_str.upper():
            bullet_lines.append(f"- 🔴 **{v_str}**")
        elif "TYPE" in v_str.upper() or "MISMATCH" in v_str.upper():
            bullet_lines.append(f"- ⚠️ **{v_str}**")
        else:
            bullet_lines.append(f"- 🟡 **{v_str}**")

    violations_body = "\n\n".join(bullet_lines) if bullet_lines else "- No contract violations."

    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"Schema Guard: {pipeline_name} drift alert",
        "sections": [
            {
                "activityTitle": title_text,
                "activitySubtitle": f"Pipeline: **{pipeline_name}** ({db_type.upper()})",
                "activityImage": "https://raw.githubusercontent.com/anilsolanki2645/schema-guard-app/main/core/static/favicon.ico",
                "facts": [
                    {"name": "Target Table", "value": table_name or "Production Catalog"},
                    {"name": "Engine", "value": db_type.upper()},
                    {"name": "Total Violations", "value": str(len(violations))},
                    {"name": "Audit Time", "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
                ],
                "markdown": True,
                "text": f"### Contract Deviations\n\n{violations_body}"
            }
        ],
        "potentialAction": [
            {
                "@type": "OpenURI",
                "name": "🔍 View in Dashboard",
                "targets": [{"os": "default", "uri": f"{app_url}/dashboard"}]
            },
            {
                "@type": "OpenURI",
                "name": "🧪 Open DDL Sandbox",
                "targets": [{"os": "default", "uri": f"{app_url}/sandbox"}]
            }
        ]
    }

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "SchemaGuard-Teams-Dispatcher/1.0"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=8) as res:
            if res.status in (200, 201, 202, 204):
                return True, "Microsoft Teams alert delivered successfully."
            return False, f"Teams responded with HTTP {res.status}"
    except Exception as e:
        logger.error(f"Failed to dispatch Teams alert to {webhook_url}: {e}")
        return False, str(e)


def sign_webhook_payload(payload_bytes: bytes, secret: str) -> str:
    """Computes HMAC-SHA256 hex digest for webhook payload."""
    if not secret:
        return ""
    return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()


def verify_webhook_signature(payload_bytes: bytes, secret: str, signature_header: str) -> bool:
    """Safely verifies HMAC-SHA256 signature against header."""
    if not secret or not signature_header:
        return False
    expected = sign_webhook_payload(payload_bytes, secret)
    provided = signature_header.replace("sha256=", "").strip()
    return hmac.compare_digest(expected, provided)


def dispatch_signed_webhook(
    url: str,
    payload: dict,
    secret: str = None,
    event: str = "schema_guard.drift_detected",
    pipeline=None,
    max_retries: int = 1,
    webhook_type: str = "custom",
    allow_internal: bool = False,
) -> tuple[bool, str, dict]:
    """
    Delivers a cryptographically signed HMAC-SHA256 webhook with SSRF validation,
    automatic retries on 5xx or connection drops, and audit logging to WebhookDeliveryLog.
    """
    is_valid, reason = validate_webhook_url(url, allow_internal=allow_internal)
    if not is_valid:
        try:
            from core.models import WebhookDeliveryLog
            WebhookDeliveryLog.objects.create(
                pipeline=pipeline,
                url=url,
                webhook_type=webhook_type,
                event=event,
                request_payload=payload,
                status_code=None,
                success=False,
                error_message=f"SSRF Validation Blocked: {reason}",
                latency_ms=0,
                retry_count=0,
            )
        except Exception:
            pass
        return False, reason, {"error": reason}

    payload_json = json.dumps(payload, default=str)
    payload_bytes = payload_json.encode("utf-8")
    delivery_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "SchemaGuard-Webhook-Dispatcher/2.0",
        "X-Schema-Guard-Event": event,
        "X-Schema-Guard-Delivery": delivery_id,
        "X-Schema-Guard-Timestamp": ts,
    }
    if secret:
        sig = sign_webhook_payload(payload_bytes, secret)
        headers["X-Schema-Guard-Signature"] = f"sha256={sig}"

    attempts = 0
    success = False
    status_code = None
    response_body = ""
    error_message = ""
    start_time = time.time()

    while attempts <= max_retries:
        attempts += 1
        try:
            req = urllib.request.Request(
                url,
                data=payload_bytes,
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=8) as res:
                status_code = getattr(res, "status", 200)
                try:
                    raw_body = res.read()
                    if isinstance(raw_body, bytes):
                        response_body = raw_body.decode("utf-8", errors="ignore")[:2000]
                    elif isinstance(raw_body, str):
                        response_body = raw_body[:2000]
                    else:
                        response_body = ""
                except Exception:
                    response_body = ""

                if status_code in (200, 201, 202, 204):
                    success = True
                    error_message = ""
                    break
                else:
                    error_message = f"Received HTTP {status_code}"
                    if status_code < 500 or attempts > max_retries:
                        break
        except urllib.error.HTTPError as e:
            status_code = e.code
            try:
                raw_body = e.read()
                response_body = raw_body.decode("utf-8", errors="ignore")[:2000] if raw_body else ""
            except Exception:
                response_body = ""
            error_message = f"HTTPError {e.code}: {e.reason}"
            if e.code < 500 or attempts > max_retries:
                break
        except Exception as e:
            status_code = None
            error_message = str(e)
            if attempts > max_retries:
                break

    latency_ms = int((time.time() - start_time) * 1000)

    log_entry = None
    try:
        from core.models import WebhookDeliveryLog
        masked_headers = dict(headers)
        if secret and "X-Schema-Guard-Signature" in masked_headers:
            masked_headers["X-Schema-Guard-Signature"] = "sha256=***[MASKED]***"

        log_entry = WebhookDeliveryLog.objects.create(
            pipeline=pipeline,
            url=url,
            webhook_type=webhook_type,
            event=event,
            status_code=status_code,
            request_headers=masked_headers,
            request_payload=payload,
            response_body=response_body,
            latency_ms=latency_ms,
            success=success,
            error_message=error_message,
            retry_count=attempts - 1,
        )
    except Exception as ex:
        logger.warning(f"Could not save WebhookDeliveryLog: {ex}")

    msg = "Webhook delivered successfully" if success else f"Webhook delivery failed: {error_message}"
    result_meta = {
        "success": success,
        "status_code": status_code,
        "latency_ms": latency_ms,
        "delivery_id": delivery_id,
        "retry_count": attempts - 1,
        "log_id": log_entry.id if log_entry else None,
        "error": error_message,
    }
    return success, msg, result_meta
