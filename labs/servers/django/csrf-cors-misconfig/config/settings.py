"""
Django settings for the csrf-cors-misconfig lab server.

============================================================================
INTENTIONALLY INSECURE - LOCAL SECURITY-TRAINING LAB ONLY. DO NOT DEPLOY.
============================================================================

This project deliberately contains a CSRF vulnerability (CWE-352) on the
state-changing role-change endpoint (see labapp/views.py:change_role_view,
decorated @csrf_exempt), weakened cookie flags (CSRF_COOKIE_HTTPONLY=False,
SESSION_COOKIE_SAMESITE=None below), and a wide-open CORS configuration
(labapp/middleware.py:PermissiveCorsMiddleware) that together let a
malicious page on ANY origin ride the victim's ambient session cookie to
force a role change -- no CSRF token required. This exists purely so a
local network-interceptor/analyzer pipeline (pkg/ncer, Rust omnisec-mitm)
has real, reproducible malicious traffic to detect. It binds to
127.0.0.1 only and must never be exposed beyond localhost or run in
production.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: this key is hardcoded and public. Fine for a local lab,
# never reuse it anywhere else.
SECRET_KEY = "django-insecure-csrf-cors-misconfig-lab-do-not-use-in-production"

# SECURITY WARNING: DEBUG is intentionally on for the lab so tracebacks are
# visible; this is part of the "insecure by design" scope.
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
    # INTENTIONALLY VULNERABLE: permissive CORS + credentials. See
    # labapp/middleware.py for the full explanation. This hand-rolled
    # middleware is the "CORS_ALLOW_ALL_ORIGINS = True" / "django-cors-
    # headers" equivalent this lab uses instead of the extra dependency.
    "labapp.middleware.PermissiveCorsMiddleware",
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
        "NAME": os.environ.get("DB_NAME", "labs_csrf_cors"),
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

# --- INTENTIONALLY VULNERABLE cookie flags ---------------------------------
# Part of the CWE-352 lab scenario: the session cookie is set without
# HttpOnly/SameSite protections, and the CSRF cookie is readable by
# JavaScript. Neither of these alone is the "whole bug" -- the actual
# exploited flaw is @csrf_exempt on change_role_view -- but weakening these
# flags too is realistic (this is exactly the kind of settings drift that
# accompanies an ad hoc "just get the mobile app / cross-origin frontend
# working" fix) and makes the cookie ride-along more convincing end-to-end.
#
# SECURITY WARNING: a production app should never set these this way.
# CSRF_COOKIE_HTTPONLY=False lets client-side JS on the SAME origin read the
# csrftoken cookie (normally desirable for SPA fetch() calls that need to
# echo it back as a header) but here it's paired with a wide-open CORS
# policy, so any origin's script can be handed the value too if it can
# otherwise get at it.
CSRF_COOKIE_HTTPONLY = False
# SECURITY WARNING: None means "send this cookie on cross-site requests
# too" (the opposite of CSRF protection's intent). This is the actual
# cookie-level half of the misconfiguration: it's what makes the victim's
# session cookie ride along on the attacker page's cross-origin request in
# the first place.
SESSION_COOKIE_SAMESITE = None
CSRF_COOKIE_SAMESITE = None

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
