"""
Django settings for the `insecure-deserialize` lab.

============================================================================
WARNING: THIS ENTIRE PROJECT IS DELIBERATELY VULNERABLE (CWE-502).
Local, isolated security-training lab only. Never deploy this configuration
anywhere reachable, and never reuse this pattern in real code.
============================================================================
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------
# Core / insecure-by-design settings
# --------------------------------------------------------------------------

# Intentionally weak, publicly-documented default secret. Overridable via
# env var for convenience, but there is no expectation of secrecy here -
# this whole app is a lab.
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY", "insecure-lab-secret-key-do-not-use-in-prod"
)

# DEBUG stays on for the lab so tracebacks are visible; the app is only
# ever bound to 127.0.0.1 (see README.md / docker-compose port mapping).
DEBUG = True

ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

# --------------------------------------------------------------------------
# Optional: if set, a fire-and-forget beacon is POSTed here whenever
# /api/session/import is used to establish a session with role != "user",
# so the lab's tracker/collector pipeline has real traffic to observe. See
# labapp/views.py::_fire_tracker_beacon.
# --------------------------------------------------------------------------
TRACKER_URL = os.environ.get("TRACKER_URL", "")

# --------------------------------------------------------------------------
# Application definition
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
# Database - MySQL, configured entirely via env vars.
# --------------------------------------------------------------------------

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "HOST": os.environ.get("DB_HOST", "127.0.0.1"),
        "PORT": os.environ.get("DB_PORT", "33306"),
        "NAME": os.environ.get("DB_NAME", "labs_insecure_deserialize"),
        "USER": os.environ.get("DB_USER", "labs"),
        "PASSWORD": os.environ.get("DB_PASSWORD", "labs_lab_pw"),
        "OPTIONS": {
            "charset": "utf8mb4",
        },
    }
}

# --------------------------------------------------------------------------
# Password validation (kept standard; irrelevant to the lab's vulnerability,
# which is a deserialization-driven role trust bypass, not a weak password
# policy).
# --------------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# --------------------------------------------------------------------------
# Internationalization
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
# Logging - make forged-role session imports loud and impossible to miss
# in server logs.
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
