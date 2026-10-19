-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
-- SPDX-License-Identifier: Apache-2.0

-- Sentin8:AI - platform AI capability layer tables.
-- Prompt registry, vector store (pgvector), inference traces, provider
-- registry (secret references only - never plaintext credentials).
-- Design: sentin8/design/sentin8-sentin8-ai-technical-design.md §6.

CREATE SCHEMA IF NOT EXISTS ai;

-- pgvector (AI design §6 - hybrid retrieval). The extension is created by
-- the pgvector/pgvector:pg18 image; guarded so plain postgres:18 dev setups
-- degrade gracefully instead of failing the whole migration.
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS vector;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pgvector unavailable - vector columns skipped (install pgvector to enable RAG)';
END $$;

CREATE TABLE IF NOT EXISTS ai.prompts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    version         INTEGER NOT NULL,
    system_text     TEXT NOT NULL DEFAULT '',
    user_text       TEXT NOT NULL DEFAULT '',
    model_primary   TEXT NOT NULL,
    model_fallback  TEXT,
    temperature     REAL,
    max_tokens      INTEGER,
    tools           JSONB NOT NULL DEFAULT '[]',
    output_schema   JSONB,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'pinned', 'retired')),
    origin          TEXT NOT NULL DEFAULT 'platform' CHECK (origin IN ('platform', 'tenant')),
    created_by      TEXT,
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name, version)
);

CREATE INDEX IF NOT EXISTS idx_ai_prompts_env_name ON ai.prompts (env_id, name, version DESC);

CREATE TABLE IF NOT EXISTS ai.providers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider        TEXT NOT NULL,                     -- 'openai' | 'anthropic' | 'ollama'
    base_url        TEXT NOT NULL,
    -- Secret REFERENCES only (AI design §7) - the credential material lives
    -- in Sentin8:Secrets; these columns name it, never store it.
    credential_ref  TEXT NOT NULL,
    models          JSONB NOT NULL DEFAULT '[]',       -- catalog validated at registration
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, provider)
);

CREATE TABLE IF NOT EXISTS ai.embeddings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    embedding       vector(1536),                      -- dimension pinned per env via registry
    content_ref     TEXT NOT NULL,                     -- Sentin8:Storage object key
    metadata        JSONB NOT NULL DEFAULT '{}',
    chunk_index     INTEGER NOT NULL DEFAULT 0,
    model           TEXT NOT NULL,
    source_id       TEXT,
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_embeddings_env ON ai.embeddings (env_id);
CREATE INDEX IF NOT EXISTS idx_ai_embeddings_source ON ai.embeddings (env_id, source_id);

CREATE TABLE IF NOT EXISTS ai.traces (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    prompt_name     TEXT NOT NULL,
    prompt_version  INTEGER,
    model           TEXT NOT NULL,
    feature         TEXT NOT NULL DEFAULT 'default',
    input_tokens    BIGINT NOT NULL DEFAULT 0,
    output_tokens   BIGINT NOT NULL DEFAULT 0,
    latency_ms      INTEGER NOT NULL DEFAULT 0,
    cache_hit       BOOLEAN NOT NULL DEFAULT false,
    cost_usd        NUMERIC(12, 8) NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'ok' CHECK (status IN ('ok', 'error')),
    subject_id      TEXT,
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_traces_env ON ai.traces (env_id);
CREATE INDEX IF NOT EXISTS idx_ai_traces_env_time ON ai.traces (env_id, created_at DESC);

-- ── Row-Level Security (mandatory hardening - principles §4.3d) ────────────

ALTER TABLE ai.prompts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.prompts FORCE ROW LEVEL SECURITY;
ALTER TABLE ai.providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.providers FORCE ROW LEVEL SECURITY;
ALTER TABLE ai.embeddings ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.embeddings FORCE ROW LEVEL SECURITY;
ALTER TABLE ai.traces ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.traces FORCE ROW LEVEL SECURITY;

-- Standard tenant match policy on every AI table (isolation only - never
-- business logic; db-design §7.0 binding rule).
DROP POLICY IF EXISTS ai_prompts_select ON ai.prompts;
CREATE POLICY ai_prompts_select ON ai.prompts
    FOR SELECT USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_prompts_insert ON ai.prompts;
CREATE POLICY ai_prompts_insert ON ai.prompts
    FOR INSERT WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_prompts_update ON ai.prompts;
CREATE POLICY ai_prompts_update ON ai.prompts
    FOR UPDATE USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_prompts_delete ON ai.prompts;
CREATE POLICY ai_prompts_delete ON ai.prompts
    FOR DELETE USING (sentin8_current_env_id() = env_id);

DROP POLICY IF EXISTS ai_providers_select ON ai.providers;
CREATE POLICY ai_providers_select ON ai.providers
    FOR SELECT USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_providers_insert ON ai.providers;
CREATE POLICY ai_providers_insert ON ai.providers
    FOR INSERT WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_providers_update ON ai.providers;
CREATE POLICY ai_providers_update ON ai.providers
    FOR UPDATE USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_providers_delete ON ai.providers;
CREATE POLICY ai_providers_delete ON ai.providers
    FOR DELETE USING (sentin8_current_env_id() = env_id);

DROP POLICY IF EXISTS ai_embeddings_select ON ai.embeddings;
CREATE POLICY ai_embeddings_select ON ai.embeddings
    FOR SELECT USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_embeddings_insert ON ai.embeddings;
CREATE POLICY ai_embeddings_insert ON ai.embeddings
    FOR INSERT WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_embeddings_delete ON ai.embeddings;
CREATE POLICY ai_embeddings_delete ON ai.embeddings
    FOR DELETE USING (sentin8_current_env_id() = env_id);

DROP POLICY IF EXISTS ai_traces_select ON ai.traces;
CREATE POLICY ai_traces_select ON ai.traces
    FOR SELECT USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_traces_insert ON ai.traces;
CREATE POLICY ai_traces_insert ON ai.traces
    FOR INSERT WITH CHECK (sentin8_current_env_id() = env_id);

-- ── Grants ─────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT, UPDATE, DELETE ON
    ai.prompts, ai.providers, ai.embeddings, ai.traces
    TO sentin8_ai_service;

-- ── 31.5.1 - per-env embedding dimension registry (vector(1536) above is
-- the default; the registry lets an env pin a different model/dimension).
CREATE TABLE IF NOT EXISTS ai.embedding_registry (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model           TEXT NOT NULL,
    dims            INTEGER NOT NULL CHECK (dims > 0),
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, model, dims)
);

-- ── 31.6.4 - DLQ for failed embedding jobs (cron DLQ pattern).
CREATE TABLE IF NOT EXISTS ai.dlq (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type        TEXT NOT NULL,                     -- 'embedding' | 'summary' | 'classification'
    payload         JSONB NOT NULL DEFAULT '{}',
    error_message   TEXT NOT NULL,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_dlq_env ON ai.dlq (env_id);
CREATE INDEX IF NOT EXISTS idx_ai_dlq_type ON ai.dlq (env_id, job_type);

-- ── 31.8.2 - per-env/feature token budgets (no Sys plan table exists -
-- research verified; budgets are AI-owned tenant configuration).
CREATE TABLE IF NOT EXISTS ai.budgets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feature             TEXT NOT NULL DEFAULT '*',       -- '*' = env-wide
    monthly_token_cap   BIGINT NOT NULL,
    enforcement         TEXT NOT NULL DEFAULT 'reject' CHECK (enforcement IN ('reject', 'degrade', 'queue')),
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    env_id              UUID NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, feature)
);

-- ── 31.9.3 - evaluation runs (golden-set scoring per prompt version).
CREATE TABLE IF NOT EXISTS ai.evaluations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    prompt_name     TEXT NOT NULL,
    prompt_version  INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed')),
    score           NUMERIC(6, 4),
    cases_total     INTEGER NOT NULL DEFAULT 0,
    cases_passed    INTEGER NOT NULL DEFAULT 0,
    results         JSONB NOT NULL DEFAULT '[]',
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_evaluations_env ON ai.evaluations (env_id, prompt_name);

-- ── 31.9.2/31.9.3 helpers - monthly token spend (reads traces) and RLS.

-- Monthly spend for budget checks: tokens consumed in the current month.
CREATE OR REPLACE FUNCTION ai.ai_monthly_tokens(p_env_id UUID, p_feature TEXT)
RETURNS BIGINT
LANGUAGE sql STABLE SET search_path = public AS $$
    SELECT COALESCE(SUM(input_tokens + output_tokens), 0)
      FROM ai.traces
     WHERE env_id = p_env_id
       AND (p_feature = '*' OR feature = p_feature OR p_feature IS NULL)
       AND created_at >= date_trunc('month', now());
$$;

ALTER TABLE ai.embedding_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.embedding_registry FORCE ROW LEVEL SECURITY;
ALTER TABLE ai.dlq ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.dlq FORCE ROW LEVEL SECURITY;
ALTER TABLE ai.budgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.budgets FORCE ROW LEVEL SECURITY;
ALTER TABLE ai.evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.evaluations FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS ai_embedding_registry_select ON ai.embedding_registry;
CREATE POLICY ai_embedding_registry_select ON ai.embedding_registry
    FOR SELECT USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_embedding_registry_insert ON ai.embedding_registry;
CREATE POLICY ai_embedding_registry_insert ON ai.embedding_registry
    FOR INSERT WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_embedding_registry_delete ON ai.embedding_registry;
CREATE POLICY ai_embedding_registry_delete ON ai.embedding_registry
    FOR DELETE USING (sentin8_current_env_id() = env_id);

DROP POLICY IF EXISTS ai_dlq_select ON ai.dlq;
CREATE POLICY ai_dlq_select ON ai.dlq
    FOR SELECT USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_dlq_insert ON ai.dlq;
CREATE POLICY ai_dlq_insert ON ai.dlq
    FOR INSERT WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_dlq_update ON ai.dlq;
CREATE POLICY ai_dlq_update ON ai.dlq
    FOR UPDATE USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_dlq_delete ON ai.dlq;
CREATE POLICY ai_dlq_delete ON ai.dlq
    FOR DELETE USING (sentin8_current_env_id() = env_id);

DROP POLICY IF EXISTS ai_budgets_select ON ai.budgets;
CREATE POLICY ai_budgets_select ON ai.budgets
    FOR SELECT USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_budgets_insert ON ai.budgets;
CREATE POLICY ai_budgets_insert ON ai.budgets
    FOR INSERT WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_budgets_update ON ai.budgets;
CREATE POLICY ai_budgets_update ON ai.budgets
    FOR UPDATE USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_budgets_delete ON ai.budgets;
CREATE POLICY ai_budgets_delete ON ai.budgets
    FOR DELETE USING (sentin8_current_env_id() = env_id);

DROP POLICY IF EXISTS ai_evaluations_select ON ai.evaluations;
CREATE POLICY ai_evaluations_select ON ai.evaluations
    FOR SELECT USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_evaluations_insert ON ai.evaluations;
CREATE POLICY ai_evaluations_insert ON ai.evaluations
    FOR INSERT WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_evaluations_update ON ai.evaluations;
CREATE POLICY ai_evaluations_update ON ai.evaluations
    FOR UPDATE USING (sentin8_current_env_id() = env_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON
    ai.embedding_registry, ai.dlq, ai.budgets, ai.evaluations
    TO sentin8_ai_service;
GRANT EXECUTE ON FUNCTION ai.ai_monthly_tokens(UUID, TEXT) TO sentin8_ai_service;

-- 31.5.2 - keyword search over chunk text (hybrid retrieval). The text is
-- stored so tsvector queries can run alongside the vector path.
ALTER TABLE ai.embeddings ADD COLUMN IF NOT EXISTS chunk_text TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_ai_embeddings_chunk_text
    ON ai.embeddings USING gin (to_tsvector('simple', chunk_text));

-- 31.3.4 - env-configurable safety filter rules (Shield-gated admin API).
-- Rules run in `sentin8:ai` BEFORE the provider call (input stage) and
-- BEFORE the response returns (output stage) - AI design §4.10. The
-- baseline injection rule is code, always active, and never configurable.
CREATE TABLE IF NOT EXISTS ai.filters (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    stage           TEXT NOT NULL CHECK (stage IN ('input', 'output')),
    blocked_terms   TEXT[] NOT NULL DEFAULT '{}',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name)
);

ALTER TABLE ai.filters ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.filters FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ai_filters_select ON ai.filters;
CREATE POLICY ai_filters_select ON ai.filters
    FOR SELECT USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_filters_insert ON ai.filters;
CREATE POLICY ai_filters_insert ON ai.filters
    FOR INSERT WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_filters_update ON ai.filters;
CREATE POLICY ai_filters_update ON ai.filters
    FOR UPDATE USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_filters_delete ON ai.filters;
CREATE POLICY ai_filters_delete ON ai.filters
    FOR DELETE USING (sentin8_current_env_id() = env_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON ai.filters TO sentin8_ai_service;

-- 31.8.1 - AI telemetry property in Sentin8:Stat (token/cost/latency/cache
-- metric envelopes attribute to `{env_id, feature, model}` here). The stat
-- platform seed only creates properties for the services it knows; the AI
-- property is seeded here where the AI tables are born (vertical-seed
-- pattern - stat init.sql NOTE on vertical telemetry).
INSERT INTO stat.properties (env_id, name, slug, timezone, retention_days)
VALUES ('00000000-0000-0000-0000-000000000002', 'Sentin8:AI Platform Telemetry', 'ai', 'UTC', 90)
ON CONFLICT DO NOTHING;

-- HNSW index for fast cosine search (31.5.1). Guarded - requires pgvector.
DO $$
BEGIN
    CREATE INDEX IF NOT EXISTS idx_ai_embeddings_hnsw ON ai.embeddings
        USING hnsw (embedding vector_cosine_ops);
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'HNSW index skipped (pgvector unavailable)';
END $$;


-- ── Local outbox (DBX, architecture-principles §6.7) ─────────────────────
-- Producer path: ai.outbox rows commit in the SAME transaction as the
-- domain change; a post-commit relay pushes them to Bus POST /v1/produce.
-- Generated from sentin8-outbox::outbox_table_sql("ai").
CREATE TABLE IF NOT EXISTS ai.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_outbox_unrelayed
    ON ai.outbox (created_at) WHERE relayed = false;
ALTER TABLE ai.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON ai.outbox;
CREATE POLICY outbox_select ON ai.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON ai.outbox;
CREATE POLICY outbox_insert ON ai.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON ai.outbox;
CREATE POLICY outbox_update ON ai.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION ai.ai_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('ai_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON ai.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON ai.outbox
    FOR EACH ROW
    EXECUTE FUNCTION ai.ai_notify_outbox();


-- ── Local audit journal (DBX §6.8) ────────────────────────────────────────
-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write), then
-- marked pushed. A Sys outage never drops audit. Generated from
-- sentin8-audit::audit_journal_sql("ai").
CREATE TABLE IF NOT EXISTS ai.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_audit_journal_unpushed
    ON ai.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE ai.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON ai.audit_journal;
CREATE POLICY audit_journal_dml ON ai.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());


-- ── Schema grants (service-owned - the 2026-10-03 ownership pass) ─────
-- This service's own schema: USAGE for its role (platform.sql no longer
-- seeds per-service USAGE; the service declares it here).
GRANT USAGE ON SCHEMA ai TO sentin8_ai_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON ai.outbox TO sentin8_ai_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ai TO sentin8_ai_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON ai.audit_journal TO sentin8_ai_service;
