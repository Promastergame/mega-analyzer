"""
WSGI config for the sqli-raw lab server.

INTENTIONALLY VULNERABLE LAB SERVER (CWE-89). See README.md.
"""
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

application = get_wsgi_application()
