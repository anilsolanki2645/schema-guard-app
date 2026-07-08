#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys

def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
    # Intercept runserver to bind to 0.0.0.0:$PORT if PORT is set (useful for Render/Heroku start commands)
    if len(sys.argv) > 1 and sys.argv[1] == 'runserver':
        port = os.environ.get('PORT')
        if port:
            # check if there's already a non-flag argument representing addrport
            has_addrport = False
            for arg in sys.argv[2:]:
                if not arg.startswith('-'):
                    has_addrport = True
                    break
            if not has_addrport:
                sys.argv.append(f"0.0.0.0:{port}")

    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)

if __name__ == '__main__':
    main()
