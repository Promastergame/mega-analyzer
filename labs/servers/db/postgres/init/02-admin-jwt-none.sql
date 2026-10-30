-- Schema + seed data for labs/servers/go/admin-jwt-none.
--
-- ⚠️ Intentionally vulnerable lab fixture — local lab only. The app itself
-- has a CWE-347 JWT `alg=none` signature-verification bypass; see that
-- server's README.md. This schema backs the normal, non-exploit login flow
-- (POST /login) so there is a real credential check to compare the forged
-- token against.

CREATE DATABASE labs_admin_jwt_none;

\c labs_admin_jwt_none

CREATE TABLE users (
    id serial PRIMARY KEY,
    username text UNIQUE,
    password_hash text,
    role text CHECK (role IN ('user', 'moderator', 'admin'))
);

-- Seed users. password_hash intentionally stores plaintext here (NOT a
-- real hash) to keep this lab's login handler a one-line comparison — the
-- vulnerability under test is JWT verification, not password storage.
-- These are documented FAKE, LOCAL-LAB-ONLY credentials, never used
-- anywhere else:
--   user:      alice_user / alice-plaintext-pw
--   moderator: mod_mike   / mike-plaintext-pw
--   admin:     root_admin / admin-plaintext-pw
INSERT INTO users (username, password_hash, role) VALUES
    ('alice_user', 'alice-plaintext-pw', 'user'),
    ('mod_mike',   'mike-plaintext-pw',  'moderator'),
    ('root_admin', 'admin-plaintext-pw', 'admin');
