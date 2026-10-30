-- Schema + seed data for labs/servers/go/admin-idor-role.
--
-- ⚠️ Intentionally vulnerable lab fixture — local lab only. The app itself
-- has a CWE-639 broken object-level authorization bug on
-- POST /api/users/{id}/role: any logged-in user (not just admins) can set
-- any user's (including their own) role to "moderator" or "admin". See
-- that server's README.md. This schema backs the normal, real login flow
-- (POST /login) so there is a real credential check ahead of the buggy
-- role-change endpoint.

CREATE DATABASE labs_admin_idor_role;

\c labs_admin_idor_role

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
--   user:      alice      / alice_lab_pw1
--   moderator: morgan     / morgan_lab_pw2
--   admin:     root_admin / admin_lab_pw3
--
-- Hashes below are bcrypt (cost factor 10) of the plaintext passwords
-- above.
INSERT INTO users (username, password_hash, role) VALUES
    ('alice',      '$2a$10$grrg5uvIz25d0uovMuie4.8qxlirRhvGSJcFKOgchBB7GX8bV0ity', 'user'),
    ('morgan',     '$2a$10$2oGSc06P6wpHbeCepOTLderDrglwikfBrWC8gfOYpE8cskpnnX13G', 'moderator'),
    ('root_admin', '$2a$10$se3sYuDM3swemFPwRXALEOvr8vEtLL4RIYhrL7CLATMEIIoWsOegi', 'admin');
