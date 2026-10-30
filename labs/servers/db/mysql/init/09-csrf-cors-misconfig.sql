-- Schema fixture for labs/servers/django/csrf-cors-misconfig.
--
-- Intentionally vulnerable lab (CWE-352: CSRF, compounded by a permissive
-- CORS misconfiguration; see that server's README.md). Unlike the Go labs
-- under labs/servers/go, this is a Django app: Django's own migrations
-- (labapp/migrations/0001_initial.py, 0002_seed_users.py) create the actual
-- tables and seed the user/moderator/admin accounts once `manage.py
-- migrate` is run against this database. This init script only needs to
-- make sure the database itself exists so the shared lab MySQL container's
-- docker-entrypoint-initdb.d mechanism can bootstrap it automatically.

CREATE DATABASE IF NOT EXISTS labs_csrf_cors CHARACTER SET utf8mb4;
