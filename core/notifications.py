import ipaddress
import json
import logging
import urllib.request
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
