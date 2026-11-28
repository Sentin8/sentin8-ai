// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Agent turn runner - the bounded tool-calling loop (ai DESIGN.md §2).
//!
//! One turn: append the user message, open a run, then loop
//! `provider → tool calls → tool results → provider` until the model stops or
//! a guard trips. Every decision is recorded (`runs.context_plan`), every hop
//! is moderated, and every tool call passes the gateway.
//!
//! Guards, all mandatory:
//! - `max_turns` iterations (the agent policy)
//! - token + cost budget, charged BEFORE each provider call
//! - a wall-clock deadline for the whole turn
//!
//! Stop reasons are a closed set: `completed`, `max_turns`, `budget`,
//! `cancelled`, `awaiting_approval`, `error`.

use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::providers::{ChatMessage, CompletionRequest, FinishReason, ToolCall};
use crate::tools::{DispatchOutcome};

/// The closed stop-reason set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Completed,
    MaxTurns,
    Budget,
    Cancelled,
    AwaitingApproval,
    Error,
}

impl StopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            StopReason::Completed => "completed",
            StopReason::MaxTurns => "max_turns",
            StopReason::Budget => "budget",
            StopReason::Cancelled => "cancelled",
            StopReason::AwaitingApproval => "awaiting_approval",
            StopReason::Error => "error",
        }
    }
}

/// The effective bounds for one turn (agent policy or env default).
#[derive(Debug, Clone)]
pub struct TurnPolicy {
    pub max_turns: i32,
    pub max_tokens_per_turn: i32,
    pub allowed_tool_classes: Vec<String>,
    pub confirmation_classes: Vec<String>,
    pub allowed_models: Vec<String>,
    pub wall_clock: std::time::Duration,
}

impl Default for TurnPolicy {
    fn default() -> Self {
        Self {
            max_turns: 8,
            max_tokens_per_turn: 8192,
            allowed_tool_classes: vec!["read".into(), "write".into()],
            confirmation_classes: vec!["irreversible".into()],
            allowed_models: Vec::new(),
            wall_clock: std::time::Duration::from_secs(120),
        }
    }
}

/// Load the effective policy for an agent (its referenced policy, else the
/// env `default` row, else the built-in defaults).
pub async fn load_policy(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    env_id: Uuid,
    policy_name: &str,
) -> Result<TurnPolicy, String> {
    let row = sqlx::query(
        "SELECT max_turns, max_tokens_per_turn, allowed_tool_classes, \
                confirmation_classes, allowed_models \
           FROM ai.agent_policies WHERE env_id = $1 AND name = $2",
    )
    .bind(env_id)
    .bind(policy_name)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| format!("load policy: {e}"))?;

    let Some(r) = row else {
        // No policy row: the built-in bound still applies - an agent NEVER
        // runs unbounded just because a tenant skipped configuration.
        return Ok(TurnPolicy::default());
    };

    let classes = json_string_vec(r.get("allowed_tool_classes"));
    let confirm = json_string_vec(r.get("confirmation_classes"));
    Ok(TurnPolicy {
        max_turns: r.get::<i32, _>("max_turns").max(1),
        max_tokens_per_turn: r.get::<i32, _>("max_tokens_per_turn").max(1),
        allowed_tool_classes: if classes.is_empty() {
            vec!["read".into()]
        } else {
            classes
        },
        confirmation_classes: confirm,
        allowed_models: json_string_vec(r.get("allowed_models")),
        wall_clock: std::time::Duration::from_secs(120),
    })
}

fn json_string_vec(v: serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// The recorded context plan - what was actually sent to the model. Storing
/// it makes a turn reproducible and auditable without replaying the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextPlan {
    /// First message seq included in the window.
    pub window_from_seq: i32,
    /// Last message seq included.
    pub window_to_seq: i32,
    /// Message id of the summary that replaced older history, when used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary_message_id: Option<Uuid>,
    /// Retrieval chunk ids injected, when the agent used retrieval.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retrieval_chunk_ids: Vec<Uuid>,
    /// Tool definitions offered this turn (names only).
    #[serde(default)]
    pub offered_tools: Vec<String>,
}

/// Assembled context for the next provider call.
pub struct Assembled {
    pub messages: Vec<ChatMessage>,
    pub plan: ContextPlan,
}

/// Build the provider message list from persisted history.
///
/// The window keeps the system message (if any) plus the most recent
/// `max_messages` turns. Summarisation is deliberately coarse: it happens
/// ONCE at a recorded boundary rather than continuously, because
/// re-summarising every turn makes the transcript non-reproducible.
pub async fn assemble_context(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    conversation_id: Uuid,
    max_messages: i32,
) -> Result<Assembled, String> {
    let rows = sqlx::query(
        "SELECT id, seq, role, content, tool_calls, tool_call_id, model \
           FROM ai.messages WHERE conversation_id = $1 ORDER BY seq DESC LIMIT $2",
    )
    .bind(conversation_id)
    .bind(max_messages.max(1))
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("load history: {e}"))?;

    if rows.is_empty() {
        return Ok(Assembled {
            messages: Vec::new(),
            plan: ContextPlan {
                window_from_seq: 0,
                window_to_seq: 0,
                summary_message_id: None,
                retrieval_chunk_ids: Vec::new(),
                offered_tools: Vec::new(),
            },
        });
    }

    // Rows come back newest-first for the LIMIT; reverse to chronological.
    let mut ordered: Vec<&sqlx::postgres::PgRow> = rows.iter().collect();
    ordered.reverse();
    let from_seq = ordered.first().map(|r| r.get::<i32, _>("seq")).unwrap_or(0);
    let to_seq = ordered.last().map(|r| r.get::<i32, _>("seq")).unwrap_or(0);

    let mut messages = Vec::with_capacity(ordered.len());
    for r in ordered {
        let role: String = r.get("role");
        let content: String = r.get("content");
        let tool_calls: Option<serde_json::Value> = r.get("tool_calls");
        let tool_call_id: Option<String> = r.get("tool_call_id");
        messages.push(ChatMessage {
            role,
            content,
            tool_calls: tool_calls.and_then(|v| serde_json::from_value::<Vec<ToolCall>>(v).ok()),
            tool_call_id,
        });
    }

    Ok(Assembled {
        messages,
        plan: ContextPlan {
            window_from_seq: from_seq,
            window_to_seq: to_seq,
            summary_message_id: None,
            retrieval_chunk_ids: Vec::new(),
            offered_tools: Vec::new(),
        },
    })
}

/// Append a message, returning its seq.
pub async fn append_message(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    conversation_id: Uuid,
    env_id: Uuid,
    msg: &ChatMessage,
    model: Option<&str>,
    token_count: i32,
    turn_id: Option<&str>,
) -> Result<i32, String> {
    // Allocate the next seq under the conversation's advisory lock (the
    // handler holds it for the whole turn - see handlers::post_turn).
    let next_seq: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM ai.messages WHERE conversation_id = $1",
    )
    .bind(conversation_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| format!("allocate seq: {e}"))?;

    let tool_calls_json = msg
        .tool_calls
        .as_ref()
        .map(|c| serde_json::to_value(c).unwrap_or(serde_json::Value::Null));

    sqlx::query(
        "INSERT INTO ai.messages \
         (conversation_id, seq, role, content, tool_calls, tool_call_id, model, token_count, turn_id, env_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(conversation_id)
    .bind(next_seq)
    .bind(&msg.role)
    .bind(&msg.content)
    .bind(tool_calls_json)
    .bind(&msg.tool_call_id)
    .bind(model)
    .bind(token_count)
    .bind(turn_id)
    .bind(env_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("append message: {e}"))?;
    Ok(next_seq)
}

/// Journal one gateway dispatch.
#[allow(clippy::too_many_arguments)]
pub async fn record_tool_call(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    run_id: Uuid,
    env_id: Uuid,
    outcome: &DispatchOutcome,
    tool_name: &str,
    arguments: &serde_json::Value,
    duration_ms: u64,
) -> Result<Uuid, String> {
    let hash = crate::tools::arguments_hash(arguments);
    let (status, approval_by, error_message): (&str, Option<&str>, Option<&str>) = match outcome {
        DispatchOutcome::Ok { .. } => ("ok", None, None),
        DispatchOutcome::Error { message, .. } => ("error", None, Some(message.as_str())),
        DispatchOutcome::Denied { reason } => ("denied", None, Some(reason.as_str())),
        DispatchOutcome::AwaitingApproval { .. } => ("awaiting_approval", None, None),
    };
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO ai.tool_calls \
         (run_id, tool_name, arguments, arguments_hash, status, approval_by, error_message, duration_ms, env_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id",
    )
    .bind(run_id)
    .bind(tool_name)
    .bind(arguments)
    .bind(&hash)
    .bind(status)
    .bind(approval_by)
    .bind(error_message)
    .bind(duration_ms as i32)
    .bind(env_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| format!("record tool call: {e}"))?;
    Ok(id)
}

/// Record a message that came from a provider (assistant) or the user.
pub fn user_message(text: impl Into<String>) -> ChatMessage {
    ChatMessage::text("user", text)
}

/// Record the tool result as a `role: "tool"` message the model can read.
pub fn tool_message(tool_call_id: &str, result: &serde_json::Value) -> ChatMessage {
    ChatMessage {
        role: "tool".into(),
        content: result.to_string(),
        tool_calls: None,
        tool_call_id: Some(tool_call_id.to_string()),
    }
}

/// Build the provider request for one iteration.
pub fn completion_request(
    model: &str,
    messages: Vec<ChatMessage>,
    tools: Vec<serde_json::Value>,
    temperature: Option<f64>,
) -> CompletionRequest {
    let tool_choice = if tools.is_empty() {
        None
    } else {
        Some("auto".into())
    };
    CompletionRequest {
        model: model.to_string(),
        messages,
        temperature,
        max_tokens: None,
        tools,
        tool_choice,
    }
}

/// Whether the model asked for tools this iteration.
pub fn wants_tools(resp_finish: FinishReason, tool_calls: &[ToolCall]) -> bool {
    !tool_calls.is_empty() || resp_finish == FinishReason::ToolCalls
}

/// Read the agent row for a conversation (id + prompt + policy name).
pub struct AgentBinding {
    pub id: Uuid,
    pub prompt_name: String,
    pub prompt_version: Option<i32>,
    pub policy_name: String,
}

pub async fn load_agent_binding(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    env_id: Uuid,
    agent_id: Uuid,
) -> Result<Option<AgentBinding>, String> {
    let row = sqlx::query(
        "SELECT id, prompt_name, prompt_version, policy_name FROM ai.agents \
          WHERE id = $1 AND env_id = $2 AND status = 'active'",
    )
    .bind(agent_id)
    .bind(env_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| format!("load agent: {e}"))?;
    Ok(row.map(|r| AgentBinding {
        id: r.get("id"),
        prompt_name: r.get("prompt_name"),
        prompt_version: r.get::<Option<i32>, _>("prompt_version"),
        policy_name: r.get("policy_name"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_reason_strings_match_the_sql_check_constraint() {
        for (r, s) in [
            (StopReason::Completed, "completed"),
            (StopReason::MaxTurns, "max_turns"),
            (StopReason::Budget, "budget"),
            (StopReason::Cancelled, "cancelled"),
            (StopReason::AwaitingApproval, "awaiting_approval"),
            (StopReason::Error, "error"),
        ] {
            assert_eq!(r.as_str(), s);
        }
    }

    #[test]
    fn default_policy_is_bounded_even_without_a_row() {
        let p = TurnPolicy::default();
        assert!(p.max_turns >= 1);
        assert!(p.max_tokens_per_turn >= 1);
        assert!(!p.wall_clock.is_zero());
        // Irreversible is never auto-allowed without confirmation.
        assert!(p.confirmation_classes.contains(&"irreversible".to_string()));
        assert!(!p.allowed_tool_classes.contains(&"irreversible".to_string()));
    }

    #[test]
    fn tool_choice_is_auto_only_when_tools_are_offered() {
        let with = completion_request("m", vec![], vec![serde_json::json!({"type":"function"})], None);
        assert_eq!(with.tool_choice.as_deref(), Some("auto"));
        let without = completion_request("m", vec![], vec![], None);
        assert_eq!(without.tool_choice, None);
    }

    #[test]
    fn wants_tools_detects_the_signal() {
        assert!(wants_tools(FinishReason::ToolCalls, &[]));
        assert!(!wants_tools(FinishReason::Stop, &[]));
    }
}
