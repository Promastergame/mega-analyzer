-- Mega-Analyzer — placeholder PostgreSQL bootstrap script.
--
-- Mounted read-only into the `postgres` service (see docker-compose.yml) at
-- /docker-entrypoint-initdb.d/init.sql. The official postgres image runs any
-- *.sql / *.sh files found there exactly once, when the data volume is first
-- initialized (an existing postgres-data volume will NOT re-run this file).
--
-- The `postgres` service is optional and illustrative: Mega-Analyzer's core
-- analyzer does not require a database to run. This script only creates an
-- empty schema placeholder so the container starts cleanly out of the box.
-- Replace it with real migrations/schema if you wire up persistent storage
-- for analysis results.

CREATE SCHEMA IF NOT EXISTS mega_analyzer;

COMMENT ON SCHEMA mega_analyzer IS
    'Placeholder schema created by init-db.sql. Add real tables/migrations here if you use PostgreSQL to store analysis results.';
