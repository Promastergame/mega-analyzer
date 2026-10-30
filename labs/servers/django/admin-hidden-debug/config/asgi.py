"""
ASGI config for the `admin-hidden-debug` lab.

Exposes the ASGI callable as a module-level variable named ``application``.
Not used by the documented `runserver` workflow (see README.md) but
included for a standard, complete project layout.
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

application = get_asgi_application()
