"""
WSGI config for the csrf-cors-misconfig lab server.

INTENTIONALLY VULNERABLE LAB SERVER (CWE-352). See README.md.
"""
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

application = get_wsgi_application()
