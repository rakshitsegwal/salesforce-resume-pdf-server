-- ═══════════════════════════════════════════════════════════════════════════
-- RENONYM AI — Database Schema
-- Run against your Railway PostgreSQL instance
-- ═══════════════════════════════════════════════════════════════════════════

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── Users ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email               VARCHAR(255) UNIQUE NOT NULL,
    name                VARCHAR(255),
    provider            VARCHAR(50) NOT NULL,          -- 'google' | 'linkedin' | 'email'
    provider_user_id    VARCHAR(255),
    avatar_url          TEXT,
    plan                VARCHAR(50) DEFAULT 'free',    -- 'free' | 'pro' | 'team' | 'enterprise'
    resume_count        INTEGER DEFAULT 0,
    ats_reports_count   INTEGER DEFAULT 0,
    anonymous_client_id VARCHAR(100),                  -- links pre-auth activity
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    last_login_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email            ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_provider_uid     ON users(provider, provider_user_id);
CREATE INDEX IF NOT EXISTS idx_users_anonymous_client ON users(anonymous_client_id);

-- ─── Saved Resumes ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS saved_resumes (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name           VARCHAR(255) DEFAULT 'My Resume',
    resume_data    JSONB       NOT NULL,
    ai_css         TEXT,
    template_style VARCHAR(100) DEFAULT 'sf-classic',
    is_active      BOOLEAN     DEFAULT true,
    created_at     TIMESTAMPTZ DEFAULT NOW(),
    updated_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_saved_resumes_user ON saved_resumes(user_id);

-- ─── ATS Reports ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ats_reports (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resume_snapshot  JSONB,
    job_description  TEXT,
    analysis_result  JSONB NOT NULL,
    ats_score        INTEGER,
    jd_match_score   INTEGER,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ats_reports_user ON ats_reports(user_id);

-- ─── Magic Link Tokens ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS magic_link_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email      VARCHAR(255) NOT NULL,
    token      VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    client_id  VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_magic_token      ON magic_link_tokens(token);
CREATE INDEX IF NOT EXISTS idx_magic_token_email ON magic_link_tokens(email);

-- ─── Future: Subscriptions ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS subscriptions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan            VARCHAR(50) NOT NULL,
    status          VARCHAR(50) DEFAULT 'active', -- 'active' | 'cancelled' | 'past_due'
    billing_period  VARCHAR(20) DEFAULT 'monthly',
    stripe_sub_id   VARCHAR(255),
    current_period_end TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
