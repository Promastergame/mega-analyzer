"""
Django settings for the tracker-beacon lab server.

INTENTIONALLY INSECURE LAB SERVER — LOCAL USE ONLY.
Binds to 127.0.0.1. Never deploy this anywhere near production.

Vulnerability class under test: undisclosed excessive telemetry / silent
data exfiltration (CWE-359 flavor). On every login and on every note
create/edit this app fires a background "analytics" beacon (see
labapp/beacon.py) to TRACKER_URL carrying far more data than a user would
reasonably expect — username, source IP, User-Agent, and full note body.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------
# Core / security (deliberately loose defaults for a local lab)
# --------------------------------------------------------------------------

SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "insecure-lab-secret-key-do-not-use-in-production-tracker-beacon",
)

# Loud reminder this is a lab, never production.
DEBUG = os.environ.get("DJANGO_DEBUG", "1") == "1"

ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

# --------------------------------------------------------------------------
# Tracker beacon target
# --------------------------------------------------------------------------
# The lab's shared local "phone home" sink (labs/servers/trackercollector).
# Default is a fake local-only hostname so the DNS-sinkhole/blocking
# exercise (pkg/internal/labdns.LabDNS) has something to intercept instead
# of a bare IP. Resolving tracker.lab.local requires either an /etc/hosts
# entry or the LabDNS server pointed at the trackercollector's bound
# address (default 127.0.0.1:18099) — see README.md.
TRACKER_URL = os.environ.get(
    "TRACKER_URL", "http://tracker.lab.local:18099/beacon/tracker-beacon"
)

# --------------------------------------------------------------------------
# Applications
# --------------------------------------------------------------------------

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "labapp",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# --------------------------------------------------------------------------
# Database (MySQL via env vars)
# --------------------------------------------------------------------------

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.environ.get("DB_NAME", "labs_tracker_beacon"),
        "USER": os.environ.get("DB_USER", "labs"),
        "PASSWORD": os.environ.get("DB_PASSWORD", "labs_lab_pw"),
        "HOST": os.environ.get("DB_HOST", "127.0.0.1"),
        "PORT": os.environ.get("DB_PORT", "33306"),
        "OPTIONS": {
            "charset": "utf8mb4",
        },
    }
}

# --------------------------------------------------------------------------
# Passwords / auth
# --------------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = []  # deliberately relaxed for a local lab

# --------------------------------------------------------------------------
# I18N
# --------------------------------------------------------------------------

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# --------------------------------------------------------------------------
# Static files
# --------------------------------------------------------------------------

STATIC_URL = "static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --------------------------------------------------------------------------
# Logging — make beacon sends loud and visible on stdout.
# --------------------------------------------------------------------------

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "labapp": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
