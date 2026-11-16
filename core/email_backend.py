from django.core.mail.backends.base import BaseEmailBackend
import urllib.request
import urllib.error
import json
import logging

logger = logging.getLogger("core.email_backend")

class ResendEmailBackend(BaseEmailBackend):
    def send_messages(self, email_messages):
        if not email_messages:
            return 0
            
        from django.conf import settings
        resend_api_key = getattr(settings, "RESEND_API_KEY", None)
        if not resend_api_key:
            logger.error("Resend API key not configured in Django settings.")
            return 0
            
        url = "https://api.resend.com/emails"
        headers = {
            "Authorization": f"Bearer {resend_api_key}",
            "Content-Type": "application/json"
        }
        
        sent_count = 0
        for message in email_messages:
            from_email = message.from_email or getattr(settings, "RESEND_FROM_EMAIL", "onboarding@resend.dev")
            to_emails = list(message.to) if message.to else []
            if not to_emails:
                logger.warning("Email message has no recipients. Skipping.")
                continue
                
            data = {
                "from": from_email,
                "to": to_emails,
                "subject": message.subject,
                "text": message.body
            }
            
            # Extract HTML content from alternative parts if present
            html_content = None
            if hasattr(message, 'alternatives') and message.alternatives:
                for alt_content, alt_type in message.alternatives:
                    if alt_type == 'text/html':
                        html_content = alt_content
                        break
            elif getattr(message, 'content_subtype', None) == 'html':
                html_content = message.body
                
            if html_content:
                data["html"] = html_content
                
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode("utf-8"),
                headers=headers,
                method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    res_data = json.loads(response.read().decode("utf-8"))
                    logger.info(f"Email sent successfully via Resend API to {to_emails}. ID: {res_data.get('id')}")
                    sent_count += 1
            except urllib.error.HTTPError as e:
                err_content = e.read().decode("utf-8")
                logger.error(f"Failed to send email via Resend HTTP API to {to_emails}. Status: {e.code}, Response: {err_content}")
            except Exception as e:
                logger.error(f"Error calling Resend API to {to_emails}: {e}")
                
        return sent_count
