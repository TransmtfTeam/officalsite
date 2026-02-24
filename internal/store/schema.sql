CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS users (
    id                   TEXT PRIMARY KEY,
    email                TEXT UNIQUE NOT NULL,
    password_hash        TEXT NOT NULL,
    display_name         TEXT NOT NULL DEFAULT '',
    avatar_url           TEXT NOT NULL DEFAULT '',
    role                 TEXT NOT NULL DEFAULT 'user', -- user | member | admin
    active               BOOLEAN NOT NULL DEFAULT true,
    totp_secret          TEXT NOT NULL DEFAULT '',
    totp_pending_secret  TEXT NOT NULL DEFAULT '',
    totp_enabled         BOOLEAN NOT NULL DEFAULT false,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oauth_clients (
    id                 TEXT PRIMARY KEY,
    client_id          TEXT UNIQUE NOT NULL,
    client_secret_hash TEXT NOT NULL,
    name               TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    redirect_uris      TEXT NOT NULL DEFAULT '',
    scopes             TEXT NOT NULL DEFAULT 'openid profile email',
    base_access        TEXT NOT NULL DEFAULT 'legacy',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_codes (
    code                  TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri          TEXT NOT NULL,
    scopes                TEXT NOT NULL,
    code_challenge        TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    nonce                 TEXT NOT NULL DEFAULT '',
    expires_at            TIMESTAMPTZ NOT NULL,
    used                  BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS access_tokens (
    id         TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    -- user_id is empty string for client_credentials tokens.
    user_id    TEXT NOT NULL DEFAULT '',
    client_id  TEXT NOT NULL,
    scopes     TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    user_id    TEXT NOT NULL DEFAULT '',
    client_id  TEXT NOT NULL,
    scopes     TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projects (
    id         TEXT PRIMARY KEY,
    slug       TEXT UNIQUE NOT NULL,
    name_zh    TEXT NOT NULL DEFAULT '',
    name_en    TEXT NOT NULL DEFAULT '',
    desc_zh    TEXT NOT NULL DEFAULT '',
    desc_en    TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'planning',
    url        TEXT NOT NULL DEFAULT '',
    tags       TEXT NOT NULL DEFAULT '[]',
    featured   BOOLEAN NOT NULL DEFAULT false,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oidc_providers (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    slug          TEXT UNIQUE NOT NULL, -- URL path: /auth/oidc/{slug}
    icon          TEXT NOT NULL DEFAULT '',
    client_id     TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    issuer_url    TEXT NOT NULL,
    scopes        TEXT NOT NULL DEFAULT 'openid email profile',
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_identities (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider   TEXT NOT NULL, -- oidc_providers.slug
    subject    TEXT NOT NULL, -- provider sub claim
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(provider, subject)
);

CREATE TABLE IF NOT EXISTS oidc_states (
    state      TEXT PRIMARY KEY,
    provider   TEXT NOT NULL,
    nonce      TEXT NOT NULL DEFAULT '',
    verifier   TEXT NOT NULL DEFAULT '', -- PKCE code_verifier
    redirect   TEXT NOT NULL DEFAULT '', -- redirect after external login
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS login_2fa_challenges (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect   TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS passkey_credentials (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT UNIQUE NOT NULL,   -- base64url encoded
    credential    TEXT NOT NULL,           -- JSON encoded webauthn.Credential
    name          TEXT NOT NULL DEFAULT 'Passkey',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS webauthn_sessions (
    id         TEXT PRIMARY KEY,
    data       TEXT NOT NULL,             -- JSON encoded webauthn.SessionData
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS client_announcements (
    client_id  TEXT PRIMARY KEY REFERENCES oauth_clients(id) ON DELETE CASCADE,
    content    TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS custom_roles (
    name        TEXT PRIMARY KEY,
    label       TEXT NOT NULL DEFAULT '',
    permissions TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS friend_links (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL DEFAULT '',
    url        TEXT NOT NULL DEFAULT '',
    icon       TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_pending_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ALTER COLUMN email_verified SET DEFAULT false;
ALTER TABLE oidc_states ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '10 minutes');
ALTER TABLE custom_roles ADD COLUMN IF NOT EXISTS permissions TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS allowed_groups TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS base_access TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE oauth_clients ALTER COLUMN base_access SET DEFAULT 'legacy';

CREATE TABLE IF NOT EXISTS user_groups (
    id         TEXT PRIMARY KEY,
    name       TEXT UNIQUE NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_group_members (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id   TEXT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS email_verifications (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS password_resets (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS password_reset_cooldowns (
    user_id           TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    last_requested_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_access_tokens_hash ON access_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_projects_sort ON projects(sort_order, created_at);
CREATE INDEX IF NOT EXISTS idx_friend_links_sort ON friend_links(sort_order, created_at);
CREATE INDEX IF NOT EXISTS idx_oidc_states_expires ON oidc_states(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_identities_lookup ON user_identities(provider, subject);
CREATE INDEX IF NOT EXISTS idx_login_2fa_expires ON login_2fa_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_passkey_user ON passkey_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_expires ON webauthn_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_group_members_user  ON user_group_members(user_id);
CREATE INDEX IF NOT EXISTS idx_user_group_members_group ON user_group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_email_verif_user         ON email_verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_email_verif_expires      ON email_verifications(expires_at);
CREATE INDEX IF NOT EXISTS idx_pwd_resets_user          ON password_resets(user_id);
CREATE INDEX IF NOT EXISTS idx_pwd_resets_expires       ON password_resets(expires_at);
