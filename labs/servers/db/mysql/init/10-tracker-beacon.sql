-- MySQL bootstrap for the tracker-beacon lab server (labs/servers/django/tracker-beacon).
-- INTENTIONALLY INSECURE LAB SERVER — LOCAL USE ONLY. Never run against production MySQL.
--
-- Django's own migrations (0001_initial + 0002_seed_lab_user) create the
-- tables and seed the demo `labuser` account; this file only needs to
-- ensure the database itself exists before `manage.py migrate` runs.

CREATE DATABASE IF NOT EXISTS labs_tracker_beacon CHARACTER SET utf8mb4;
