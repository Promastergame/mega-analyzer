-- Schema + seed data for labs/servers/go/admin-backdoor-header.
--
-- ⚠️ Intentionally vulnerable lab fixture — local lab only. The app itself
-- has a CWE-798 hardcoded backdoor header (X-Debug-Role: admin) that
-- bypasses this table entirely; see that server's README.md. This schema
-- exists so the normal, non-backdoor login/session flow also has something
-- real to talk to.

CREATE DATABASE labs_admin_backdoor_header;

\c labs_admin_backdoor_header

CREATE TABLE users (
    id serial PRIMARY KEY,
    username text UNIQUE NOT NULL,
    password_hash text NOT NULL,
    role text NOT NULL CHECK (role IN ('user', 'moderator', 'admin'))
);

CREATE TABLE sessions (
    id serial PRIMARY KEY,
    user_id int REFERENCES users(id),
    token text UNIQUE NOT NULL,
    created_at timestamptz DEFAULT now()
);

-- Seed users. Plaintext seed passwords (FAKE, LOCAL-LAB-ONLY credentials --
-- never used anywhere else, safe to keep in plaintext here for lab setup):
--   user:      alice      / correcthorsebatterystaple
--   moderator: mod-morgan / modpassword123
--   admin:     root-admin / adminpassword
--
-- Hashes below are bcrypt (cost factor 4, deliberately cheap since this is
-- a throwaway local lab, not production) of the plaintext passwords above.
INSERT INTO users (username, password_hash, role) VALUES
    ('alice',      '$2a$04$BQL.RfFD2mw9thLpVGbmJuF/IISH0f1ozLQViIUeFlEB9F2LFOnYq', 'user'),
    ('mod-morgan', '$2a$04$R5H7ySxLrs3mKbv3PsUwpOTscZ4lYENuwgOW83OwynimtDYUc844a', 'moderator'),
    ('root-admin', '$2a$04$4mIjLfTWr0eFlbJiqvAkROxeFPhAQgWLNMbXNfJhCPnhJs0ZKWRb2', 'admin');
