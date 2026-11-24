#!/usr/bin/env python
"""
Standalone Schema Guard CLI Entrypoint.
Delegates directly to Django's schemaguard management command.
"""
import os
import sys

# Ensure project root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
    import django
    django.setup()
    from django.core.management import call_command
    args = sys.argv[1:]
    call_command("schemaguard", *args)
