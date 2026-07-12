import sys
import os
import django

def main():
    if len(sys.argv) < 3:
        print("Usage: send_email_diagnostic.py <email> <code>")
        sys.exit(1)
        
    email = sys.argv[1]
    code = sys.argv[2]
    
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
    django.setup()
    
    from django.core.mail import send_mail
    from django.conf import settings
    
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
            <tr>
                <td height="4" style="background: linear-gradient(90deg, #fbbf24, #d97706, #fb7185);"></td>
            </tr>
            <tr>
                <td style="padding: 40px 40px 20px 40px; text-align: center;">
                    <div style="display: inline-block; background: rgba(245, 158, 11, 0.08); border: 1.5px solid rgba(245, 158, 11, 0.3); border-radius: 12px; padding: 12px 20px; text-align: center; margin-bottom: 25px;">
                        <span style="font-size: 24px; vertical-align: middle;">🔑</span>
                        <span style="font-size: 18px; font-weight: 800; color: #ffffff; letter-spacing: 1px; vertical-align: middle; margin-left: 8px; font-family: 'Outfit', sans-serif;">Schema <span style="color: #fbbf24;">Guard</span></span>
                    </div>
                    <h1 style="color: #ffffff; font-size: 24px; font-weight: 800; margin: 0; font-family: 'Outfit', sans-serif; letter-spacing: -0.02em;">Password Reset Request</h1>
                </td>
            </tr>
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
    
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
        html_message=html_message
    )
    print("SUCCESS")

if __name__ == "__main__":
    main()
