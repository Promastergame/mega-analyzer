#!/usr/bin/env python
"""Django's command-line utility for administrative tasks.

INTENTIONALLY VULNERABLE LAB SERVER (undisclosed telemetry / CWE-359-ish).
See README.md before running this anywhere but an isolated local sandbox.
This app fires a background "analytics" beacon on login and on every note
create/edit that phones home to TRACKER_URL with more data than a user
would expect (username, IP, User-Agent, full note body). That beacon is
the deliberate target for this lab's DNS-blocking / mitm-detection tests.
"""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
