#!/usr/bin/env python
"""Django's command-line utility for administrative tasks.

Part of the `admin-hidden-debug` intentionally-vulnerable lab server.
See README.md before running this anywhere but a local, isolated lab.
"""
import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment? Run "
            "`pip install -r requirements.txt` first."
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
