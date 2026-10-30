-- labs/servers/go/sqli-login schema + seed data.
--
-- Local lab use only. Backs an INTENTIONALLY VULNERABLE (CWE-89) login
-- handler at labs/servers/go/sqli-login — see that directory's README.md.
--
-- INTENTIONAL SIMPLIFICATION, not a second bug: in a real application the
-- `password_hash` column would hold a salted hash (bcrypt/argon2/etc.) and
-- the server would hash-compare rather than compare raw strings. Here
-- `password_hash` literally stores the plaintext password so the SQLi demo
-- stays self-contained (no bcrypt library / hashing step needed to prove
-- the injection). The vulnerability this lab demonstrates is the SQL
-- injection in query.go's buildLoginQuery, not this plaintext storage —
-- please don't "fix" this file into hashing without also updating the lab
-- server's LoginRaw comparison logic to match.

CREATE DATABASE labs_sqli_login;

\c labs_sqli_login

CREATE TABLE users (
    id            serial PRIMARY KEY,
    username      text UNIQUE NOT NULL,
    password_hash text NOT NULL, -- plaintext password for this lab, see note above
    role          text NOT NULL CHECK (role IN ('user', 'moderator', 'admin'))
);

-- Fake, documented lab-only credentials. Never reuse these anywhere real.
INSERT INTO users (username, password_hash, role) VALUES
    ('user',      'user_lab_pw',      'user'),
    ('moderator', 'moderator_lab_pw', 'moderator'),
    ('admin',     'admin_lab_pw',     'admin');
