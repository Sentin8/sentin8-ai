-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
-- SPDX-License-Identifier: Apache-2.0

-- ── AI-2: embedding model_version (dual-write/dual-read + re-embed sweep)
-- `model_version` discriminates embedding generations: the registry
-- (`ai.embedding_registry`) pins the ACTIVE (model, dims) per env and
-- carries the version; rows written by a given generation stamp the same
-- version. The Cron sweep re-enqueues embedding jobs for rows whose
-- version trails the registry-active one - pgvector's typmod makes
-- per-model dimensions a REINDEX concern (greenfield: re-run init with
-- the target model pinned); the version column is the dual-read
-- discriminator that tells the sweep which rows are stale.

ALTER TABLE ai.embeddings
    ADD COLUMN IF NOT EXISTS model_version TEXT NOT NULL DEFAULT 'v1';

CREATE INDEX IF NOT EXISTS idx_ai_embeddings_model_version
    ON ai.embeddings (env_id, model, model_version);

ALTER TABLE ai.embedding_registry
    ADD COLUMN IF NOT EXISTS version TEXT NOT NULL DEFAULT 'v1';

-- Sweep helper (SECURITY DEFINER - the cron proxy-back runs context-less
-- and FORCE RLS hides rows without context; returns only ids + versions,
-- no embedding content).
CREATE OR REPLACE FUNCTION ai.ai_stale_model_versions(
    p_env UUID,
    p_model TEXT,
    p_version TEXT
) RETURNS TABLE (id UUID, source_id TEXT)
LANGUAGE plpgsql SECURITY DEFINER AS $fn$
BEGIN
    RETURN QUERY
        SELECT e.id, e.source_id
          FROM ai.embeddings e
         WHERE e.env_id = p_env
           AND e.model = p_model
           AND e.model_version <> p_version
         ORDER BY e.created_at
         LIMIT 50;
END;
$fn$;