#!/usr/bin/env python
"""
Standalone Schema Guard CLI Entrypoint.
Delegates directly to Django's schemaguard management command.
"""
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "schemaguard_app.settings")
    import django
    django.setup()
    from django.core.management import call_command
    args = sys.argv[1:]
    call_command("schemaguard", *args)
