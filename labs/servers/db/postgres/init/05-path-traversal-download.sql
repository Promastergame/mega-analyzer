-- Schema + seed data for labs/servers/go/path-traversal-download.
--
-- ⚠️ Intentionally vulnerable lab fixture — local lab only. The app itself
-- has a CWE-22 path-traversal bug in GET /files?name=... that lets an
-- attacker read files/config/admin_secrets.txt (planted outside the
-- server's files/ root) via "../config/admin_secrets.txt". That file
-- contains the exact bootstrap_token seeded below for the admin user, so
-- the leaked token can be replayed against POST /login-with-token to mint
-- a full admin session with no username or password ever presented.
-- See that server's README.md.

CREATE DATABASE labs_path_traversal;

\c labs_path_traversal

CREATE TABLE users (
    id serial PRIMARY KEY,
    username text UNIQUE NOT NULL,
    password_hash text,
    role text NOT NULL CHECK (role IN ('user', 'moderator', 'admin')),
    bootstrap_token text UNIQUE
);

-- Seed users. Plaintext seed passwords (FAKE, LOCAL-LAB-ONLY credentials --
-- never used anywhere else, safe to keep in plaintext here for lab setup):
--   user:      dana       / danapassword
--   moderator: mod-morgan / modpassword123
--   admin:     root-admin / adminpassword (never actually needed -- see below)
--
-- Hashes below are bcrypt (cost factor 4, deliberately cheap since this is
-- a throwaway local lab, not production) of the plaintext passwords above.
-- The admin's password_hash is included purely for schema realism: the
-- app's /login-with-token flow never checks it, only bootstrap_token,
-- which is the whole point of the CWE-22 -> hidden-admin-access chain.
--
-- IMPORTANT: bootstrap_token below MUST match the fake token planted in
-- DATA_DIR/config/admin_secrets.txt by the server on startup (see
-- seededBootstrapToken in main.go). Keep these two values in sync:
--   LAB-ADMIN-BOOTSTRAP-9f2a7c
INSERT INTO users (username, password_hash, role, bootstrap_token) VALUES
    ('dana',       '$2a$04$BQL.RfFD2mw9thLpVGbmJuF/IISH0f1ozLQViIUeFlEB9F2LFOnYq', 'user',      NULL),
    ('mod-morgan', '$2a$04$R5H7ySxLrs3mKbv3PsUwpOTscZ4lYENuwgOW83OwynimtDYUc844a', 'moderator', NULL),
    ('root-admin', '$2a$04$4mIjLfTWr0eFlbJiqvAkROxeFPhAQgWLNMbXNfJhCPnhJs0ZKWRb2', 'admin',     'LAB-ADMIN-BOOTSTRAP-9f2a7c');
