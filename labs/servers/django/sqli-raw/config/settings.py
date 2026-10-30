"""
Django settings for the sqli-raw lab server.

============================================================================
INTENTIONALLY INSECURE - LOCAL SECURITY-TRAINING LAB ONLY. DO NOT DEPLOY.
============================================================================

This project deliberately contains a SQL injection vulnerability (CWE-89) in
labapp/queries.py so that a local network-interceptor/analyzer pipeline has
real, reproducible malicious traffic to detect. It binds to 127.0.0.1 only
and must never be exposed beyond localhost or run in production.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: this key is hardcoded and public. Fine for a local lab,
# never reuse it anywhere else.
SECRET_KEY = "django-insecure-sqli-raw-lab-do-not-use-in-production"

# SECURITY WARNING: DEBUG is intentionally on for the lab so tracebacks and
# query context are visible; this is part of the "insecure by design" scope.
DEBUG = True

ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

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

# --- Database -------------------------------------------------------------
# MySQL, configured entirely via environment variables so this lab can be
# pointed at the shared labs MySQL instance defined under
# labs/servers/db/mysql without editing code.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": os.environ.get("DB_NAME", "labs_sqli_raw"),
        "USER": os.environ.get("DB_USER", "labs"),
        "PASSWORD": os.environ.get("DB_PASSWORD", "labs_lab_pw"),
        "HOST": os.environ.get("DB_HOST", "127.0.0.1"),
        "PORT": os.environ.get("DB_PORT", "33306"),
        "OPTIONS": {
            "charset": "utf8mb4",
        },
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Lab-specific config ---------------------------------------------------
# Best-effort beacon target for the local trackercollector sink
# (labs/servers/trackercollector). Requests to it are fire-and-forget and
# must never block or fail the HTTP response.
TRACKER_URL = os.environ.get("TRACKER_URL", "")

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
