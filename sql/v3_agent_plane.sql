-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
-- SPDX-License-Identifier: Apache-2.0

-- v3 - agent plane (ai DESIGN.md §3). Multi-turn conversations, the tenant
-- tool registry, named agents + policies, and human approvals. Applied by
-- `vertical enroll` as migration version 3; `init.sql` (v1) owns the base
-- tables and is not re-run.

-- ══════════════════════════════════════════════════════════════════════════
-- Agent plane (ai DESIGN.md §3) - conversations, tools, agents, approvals.
--
-- Multi-turn agents: a conversation holds the transcript, a run is one
-- bounded turn, a tool call is one gateway dispatch. State is AI-owned; a
-- Func module or Flow workflow addresses a conversation by id and never
-- holds history (the sandbox has no durable state by design).
-- ══════════════════════════════════════════════════════════════════════════

-- Tenant-authored tools. A tool is DATA, not a code path: adding a
-- capability never edits AI code. `kind` selects the dispatch route;
-- `target` names the owner-side reference (never a URL).
CREATE TABLE IF NOT EXISTS ai.tools (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    input_schema        JSONB NOT NULL DEFAULT '{"type":"object","properties":{}}',
    kind                TEXT NOT NULL CHECK (kind IN ('http_action', 'flow_workflow', 'func_module', 'builtin')),
    target              JSONB NOT NULL DEFAULT '{}',
    required_scope      TEXT NOT NULL DEFAULT '',
    side_effect         TEXT NOT NULL DEFAULT 'read' CHECK (side_effect IN ('read', 'write', 'irreversible')),
    requires_confirmation BOOLEAN NOT NULL DEFAULT false,
    rate_limit_per_min  INTEGER NOT NULL DEFAULT 0,     -- 0 = unlimited
    timeout_ms          INTEGER NOT NULL DEFAULT 30000,
    max_response_bytes  INTEGER NOT NULL DEFAULT 65536,
    enabled             BOOLEAN NOT NULL DEFAULT true,
    env_id              UUID NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name)
);

-- Per-env agent policy - the bounds document. An agent either references a
-- policy or inherits the env default ('default' name).
CREATE TABLE IF NOT EXISTS ai.agent_policies (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL DEFAULT 'default',
    allowed_models      JSONB NOT NULL DEFAULT '[]',
    max_turns           INTEGER NOT NULL DEFAULT 8 CHECK (max_turns > 0),
    max_tokens_per_turn INTEGER NOT NULL DEFAULT 8192 CHECK (max_tokens_per_turn > 0),
    allowed_tool_classes JSONB NOT NULL DEFAULT '["read","write"]',
    confirmation_classes JSONB NOT NULL DEFAULT '["irreversible"]',
    retention_days      INTEGER NOT NULL DEFAULT 90,
    env_id              UUID NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name)
);

-- Named agent: a prompt binding + a tool set + a policy.
CREATE TABLE IF NOT EXISTS ai.agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    prompt_name     TEXT NOT NULL,
    prompt_version  INTEGER,
    policy_name     TEXT NOT NULL DEFAULT 'default',
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, name)
);

-- Which tools an agent may use (the allowlist is a relation, not JSON).
CREATE TABLE IF NOT EXISTS ai.agent_tools (
    agent_id    UUID NOT NULL REFERENCES ai.agents(id) ON DELETE CASCADE,
    tool_id     UUID NOT NULL REFERENCES ai.tools(id) ON DELETE CASCADE,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    env_id      UUID NOT NULL,
    PRIMARY KEY (agent_id, tool_id)
);

-- A conversation: the transcript owner. Holder-scoped (owner_sub) - visible
-- to the owning user plus env/org admins via context-stamped flags.
CREATE TABLE IF NOT EXISTS ai.conversations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_sub       TEXT NOT NULL,
    agent_id        UUID REFERENCES ai.agents(id) ON DELETE SET NULL,
    title           TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'archived')),
    turn_count      INTEGER NOT NULL DEFAULT 0,
    tokens_total    BIGINT NOT NULL DEFAULT 0,
    cost_total      NUMERIC(14, 8) NOT NULL DEFAULT 0,
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_conversations_env_owner
    ON ai.conversations (env_id, owner_sub, updated_at DESC);

-- Ordered messages. `seq` is unique per conversation: turn ordering AND
-- idempotent append. `turn_id` on the user message makes a retried turn
-- return the stored answer instead of appending a duplicate.
CREATE TABLE IF NOT EXISTS ai.messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES ai.conversations(id) ON DELETE CASCADE,
    seq             INTEGER NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('system', 'user', 'assistant', 'tool')),
    content         TEXT NOT NULL DEFAULT '',
    tool_calls      JSONB,
    tool_call_id    TEXT,
    model           TEXT,
    run_id          UUID,
    token_count     INTEGER NOT NULL DEFAULT 0,
    turn_id         TEXT,
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (conversation_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_ai_messages_conv_seq ON ai.messages (conversation_id, seq);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_messages_turn_idempotency
    ON ai.messages (conversation_id, turn_id) WHERE turn_id IS NOT NULL AND role = 'user';

-- One run per turn - the recorded decision trail.
CREATE TABLE IF NOT EXISTS ai.runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES ai.conversations(id) ON DELETE CASCADE,
    turn            INTEGER NOT NULL,
    stop_reason     TEXT CHECK (stop_reason IN ('completed', 'max_turns', 'budget', 'cancelled', 'awaiting_approval', 'error')),
    context_plan    JSONB NOT NULL DEFAULT '{}',
    iterations      INTEGER NOT NULL DEFAULT 0,
    input_tokens    BIGINT NOT NULL DEFAULT 0,
    output_tokens   BIGINT NOT NULL DEFAULT 0,
    agent_token_jti TEXT,
    error_message   TEXT,
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (conversation_id, turn)
);
CREATE INDEX IF NOT EXISTS idx_ai_runs_conv ON ai.runs (conversation_id, turn DESC);

-- One row per gateway dispatch - arguments_hash makes a mutation provable
-- after the fact without replaying the model.
CREATE TABLE IF NOT EXISTS ai.tool_calls (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID NOT NULL REFERENCES ai.runs(id) ON DELETE CASCADE,
    tool_name       TEXT NOT NULL,
    arguments       JSONB NOT NULL DEFAULT '{}',
    arguments_hash  TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'ok' CHECK (status IN ('ok', 'error', 'denied', 'timeout', 'awaiting_approval')),
    approval_by     TEXT,
    error_message   TEXT,
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_tool_calls_run ON ai.tool_calls (run_id);

-- Human approval for an irreversible action. A pending approval past its
-- deadline expires and fails the run - an agent never parks forever.
CREATE TABLE IF NOT EXISTS ai.approvals (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID NOT NULL REFERENCES ai.runs(id) ON DELETE CASCADE,
    conversation_id UUID NOT NULL REFERENCES ai.conversations(id) ON DELETE CASCADE,
    tool_name       TEXT NOT NULL,
    arguments       JSONB NOT NULL DEFAULT '{}',
    state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'denied', 'expired')),
    decided_by      TEXT,
    decided_at      TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '24 hours'),
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_approvals_pending
    ON ai.approvals (env_id) WHERE state = 'pending';

-- Traces attribute an inference to the turn that caused it.
ALTER TABLE ai.traces ADD COLUMN IF NOT EXISTS run_id UUID;

-- ── RLS: agent plane ──────────────────────────────────────────────────────
ALTER TABLE ai.tools ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.tools FORCE ROW LEVEL SECURITY;
ALTER TABLE ai.agent_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.agent_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE ai.agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.agents FORCE ROW LEVEL SECURITY;
ALTER TABLE ai.agent_tools ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.agent_tools FORCE ROW LEVEL SECURITY;
ALTER TABLE ai.conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.conversations FORCE ROW LEVEL SECURITY;
ALTER TABLE ai.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.messages FORCE ROW LEVEL SECURITY;
ALTER TABLE ai.runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.runs FORCE ROW LEVEL SECURITY;
ALTER TABLE ai.tool_calls ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.tool_calls FORCE ROW LEVEL SECURITY;
ALTER TABLE ai.approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai.approvals FORCE ROW LEVEL SECURITY;

-- Tenant-config tables: plain env isolation.
DROP POLICY IF EXISTS ai_tools_env ON ai.tools;
CREATE POLICY ai_tools_env ON ai.tools
    USING (sentin8_current_env_id() = env_id)
    WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_agent_policies_env ON ai.agent_policies;
CREATE POLICY ai_agent_policies_env ON ai.agent_policies
    USING (sentin8_current_env_id() = env_id)
    WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_agents_env ON ai.agents;
CREATE POLICY ai_agents_env ON ai.agents
    USING (sentin8_current_env_id() = env_id)
    WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS ai_agent_tools_env ON ai.agent_tools;
CREATE POLICY ai_agent_tools_env ON ai.agent_tools
    USING (sentin8_current_env_id() = env_id)
    WITH CHECK (sentin8_current_env_id() = env_id);

-- Conversations are HOLDER-scoped (architecture-principles §4.3c): the row
-- is visible to its owner, and to env/org admins through the
-- context-stamped admin flags resolved at set-context time.
DROP POLICY IF EXISTS ai_conversations_scope ON ai.conversations;
CREATE POLICY ai_conversations_scope ON ai.conversations
    USING (
        sentin8_current_env_id() = env_id
        AND (owner_sub = sentin8_current_subject_id() OR sentin8_is_env_admin())
    )
    WITH CHECK (
        sentin8_current_env_id() = env_id
        AND (owner_sub = sentin8_current_subject_id() OR sentin8_is_env_admin())
    );

-- Child tables inherit the conversation scope through their parent.
DROP POLICY IF EXISTS ai_messages_scope ON ai.messages;
CREATE POLICY ai_messages_scope ON ai.messages
    USING (
        sentin8_current_env_id() = env_id
        AND EXISTS (
            SELECT 1 FROM ai.conversations c
             WHERE c.id = ai.messages.conversation_id
               AND (c.owner_sub = sentin8_current_subject_id() OR sentin8_is_env_admin())
        )
    )
    WITH CHECK (
        sentin8_current_env_id() = env_id
        AND EXISTS (
            SELECT 1 FROM ai.conversations c
             WHERE c.id = ai.messages.conversation_id
               AND (c.owner_sub = sentin8_current_subject_id() OR sentin8_is_env_admin())
        )
    );

DROP POLICY IF EXISTS ai_runs_scope ON ai.runs;
CREATE POLICY ai_runs_scope ON ai.runs
    USING (
        sentin8_current_env_id() = env_id
        AND EXISTS (
            SELECT 1 FROM ai.conversations c
             WHERE c.id = ai.runs.conversation_id
               AND (c.owner_sub = sentin8_current_subject_id() OR sentin8_is_env_admin())
        )
    )
    WITH CHECK (
        sentin8_current_env_id() = env_id
        AND EXISTS (
            SELECT 1 FROM ai.conversations c
             WHERE c.id = ai.runs.conversation_id
               AND (c.owner_sub = sentin8_current_subject_id() OR sentin8_is_env_admin())
        )
    );

DROP POLICY IF EXISTS ai_tool_calls_scope ON ai.tool_calls;
CREATE POLICY ai_tool_calls_scope ON ai.tool_calls
    USING (
        sentin8_current_env_id() = env_id
        AND EXISTS (
            SELECT 1 FROM ai.runs r
              JOIN ai.conversations c ON c.id = r.conversation_id
             WHERE r.id = ai.tool_calls.run_id
               AND (c.owner_sub = sentin8_current_subject_id() OR sentin8_is_env_admin())
        )
    )
    WITH CHECK (
        sentin8_current_env_id() = env_id
        AND EXISTS (
            SELECT 1 FROM ai.runs r
              JOIN ai.conversations c ON c.id = r.conversation_id
             WHERE r.id = ai.tool_calls.run_id
               AND (c.owner_sub = sentin8_current_subject_id() OR sentin8_is_env_admin())
        )
    );

DROP POLICY IF EXISTS ai_approvals_scope ON ai.approvals;
CREATE POLICY ai_approvals_scope ON ai.approvals
    USING (
        sentin8_current_env_id() = env_id
        AND EXISTS (
            SELECT 1 FROM ai.conversations c
             WHERE c.id = ai.approvals.conversation_id
               AND (c.owner_sub = sentin8_current_subject_id() OR sentin8_is_env_admin())
        )
    )
    WITH CHECK (
        sentin8_current_env_id() = env_id
        AND EXISTS (
            SELECT 1 FROM ai.conversations c
             WHERE c.id = ai.approvals.conversation_id
               AND (c.owner_sub = sentin8_current_subject_id() OR sentin8_is_env_admin())
        )
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON
    ai.tools, ai.agent_policies, ai.agents, ai.agent_tools, ai.conversations,
    ai.messages, ai.runs, ai.tool_calls, ai.approvals
    TO sentin8_ai_service;

-- Conversation token/cost rollup, updated at each turn close (same tx as
-- the last message + run update).
CREATE OR REPLACE FUNCTION ai.ai_conversation_touch(
    p_conversation_id UUID,
    p_tokens BIGINT,
    p_cost NUMERIC
) RETURNS VOID
LANGUAGE sql SET search_path = public AS $$
    UPDATE ai.conversations
       SET turn_count = turn_count + 1,
           tokens_total = tokens_total + COALESCE(p_tokens, 0),
           cost_total = cost_total + COALESCE(p_cost, 0),
           updated_at = now()
     WHERE id = p_conversation_id;
$$;
GRANT EXECUTE ON FUNCTION ai.ai_conversation_touch(UUID, BIGINT, NUMERIC) TO sentin8_ai_service;
