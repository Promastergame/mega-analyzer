-- sqli-raw lab: minimal DB provisioning only.
--
-- Django owns the real schema via migrations (see
-- labs/servers/django/sqli-raw/README.md): run `python manage.py migrate`
-- from that directory to create the actual tables (auth_user,
-- django_session, labapp_userprofile, ...) and seed the demo
-- user/moderator/admin accounts (labapp/migrations/0002_seed_users.py).
-- This file intentionally does nothing beyond that.

CREATE DATABASE IF NOT EXISTS labs_sqli_raw CHARACTER SET utf8mb4;

-- Matches config/settings.py's default DB_USER/DB_PASSWORD env var
-- defaults for this lab.
CREATE USER IF NOT EXISTS 'labs'@'%' IDENTIFIED BY 'labs_lab_pw';
GRANT ALL PRIVILEGES ON labs_sqli_raw.* TO 'labs'@'%';
FLUSH PRIVILEGES;
