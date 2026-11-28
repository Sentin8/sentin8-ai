// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Conversation plane HTTP handlers (ai DESIGN.md §4.1).
//!
//! Groups: conversations, turns, tools, agents/policies, approvals. Every
//! handler follows the platform pipeline: bearer verify, Shield
//! `require_policy` (step 5, the only gate), required `target_env_id`, then a
//! tenant transaction that stamps the caller's subject so holder-scoped RLS
//! resolves.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::auth;
use crate::handlers::{AppState, TargetEnvQuery};
use crate::providers::{ChatMessage, ToolCall};
use crate::turn::{self, StopReason};
use crate::tools::{self, DispatchOutcome};

/// Parse the caller's live scopes into the list form the gateway consumes.
fn scopes_of(a: &auth::AuthContext) -> Vec<String> {
    a.claims
        .scope
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

// ── Conversations ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateConversationRequest {
    /// Agent name to bind. Required - a conversation without an agent has no
    /// prompt, no tools, and no policy.
    pub agent_name: String,
    #[serde(default)]
    pub title: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ConversationRecord {
    pub id: Uuid,
    pub title: String,
    pub state: String,
    pub agent_id: Option<Uuid>,
    pub turn_count: i32,
    pub tokens_total: i64,
    pub cost_total: f64,
    pub created_at: String,
    pub updated_at: String,
}

fn conversation_from_row(r: &sqlx::postgres::PgRow) -> ConversationRecord {
    ConversationRecord {
        id: r.get("id"),
        title: r.get("title"),
        state: r.get("state"),
        agent_id: r.get("agent_id"),
        turn_count: r.get("turn_count"),
        tokens_total: r.get("tokens_total"),
        // NUMERIC decodes to f64 through sqlx's `f64` support (the column is
        // a precision-8 monetary rollup; f64 is exact enough for display).
        cost_total: r.try_get::<f64, _>("cost_total").unwrap_or(0.0),
        created_at: r
            .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
            .to_rfc3339(),
        updated_at: r
            .get::<chrono::DateTime<chrono::Utc>, _>("updated_at")
            .to_rfc3339(),
    }
}

/// `POST /v1/conversations` - open a conversation bound to an agent.
#[utoipa::path(
    post,
    operation_id = "ai.conversation.create",
    path = "/v1/conversations",
    request_body = CreateConversationRequest,
    params(("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Conversation created", body = ConversationRecord)),
    security(("sentin8:ai:conversation:write" = [])),
    tag = "ai",
)]
pub async fn create_conversation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(body): Json<CreateConversationRequest>,
) -> Result<Json<ConversationRecord>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:conversation:write"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;

    let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
    let agent_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM ai.agents WHERE env_id = $1 AND name = $2 AND status = 'active'",
    )
    .bind(env_id)
    .bind(&body.agent_name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(crate::handlers::err_db_pub)?;
    let agent_id = agent_id.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("agent '{}' not found", body.agent_name),
        )
    })?;

    let title = if body.title.trim().is_empty() {
        format!("Conversation with {}", body.agent_name)
    } else {
        body.title.clone()
    };
    let row = sqlx::query(
        "INSERT INTO ai.conversations (owner_sub, agent_id, title, env_id) \
         VALUES ($1,$2,$3,$4) RETURNING *",
    )
    .bind(&a.claims.sub)
    .bind(agent_id)
    .bind(&title)
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(crate::handlers::err_db_pub)?;
    crate::handlers::emit_event_tx(
        &mut tx,
        env_id,
        "sentin8:ai:conversation:created",
        &serde_json::json!({ "conversation_id": row.get::<Uuid, _>("id"), "agent": body.agent_name }),
    )
    .await?;
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    Ok(Json(conversation_from_row(&row)))
}

/// `GET /v1/conversations` - list the caller's conversations.
#[utoipa::path(
    get,
    operation_id = "ai.conversation.list",
    path = "/v1/conversations",
    params(("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Conversations", body = Vec<ConversationRecord>)),
    security(("sentin8:ai:conversation:read" = [])),
    tag = "ai",
)]
pub async fn list_conversations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<Vec<ConversationRecord>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:conversation:read"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
    let rows = sqlx::query(
        "SELECT * FROM ai.conversations WHERE env_id = $1 ORDER BY updated_at DESC LIMIT 100",
    )
    .bind(env_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(crate::handlers::err_db_pub)?;
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    Ok(Json(rows.iter().map(conversation_from_row).collect()))
}

/// `GET /v1/conversations/{id}` - one conversation.
#[utoipa::path(
    get,
    operation_id = "ai.conversation.get",
    path = "/v1/conversations/{id}",
    params(("id" = Uuid, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Conversation", body = ConversationRecord)),
    security(("sentin8:ai:conversation:read" = [])),
    tag = "ai",
)]
pub async fn get_conversation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConversationRecord>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:conversation:read"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
    let row = sqlx::query("SELECT * FROM ai.conversations WHERE id = $1 AND env_id = $2")
        .bind(id)
        .bind(env_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(crate::handlers::err_db_pub)?
        .ok_or((StatusCode::NOT_FOUND, "conversation not found".into()))?;
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    Ok(Json(conversation_from_row(&row)))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateConversationRequest {
    #[serde(default)]
    pub title: Option<String>,
    /// `active` | `archived`.
    #[serde(default)]
    pub state: Option<String>,
}

/// `PUT /v1/conversations/{id}` - rename or archive.
#[utoipa::path(
    put,
    operation_id = "ai.conversation.update",
    path = "/v1/conversations/{id}",
    request_body = UpdateConversationRequest,
    params(("id" = Uuid, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Conversation updated", body = ConversationRecord)),
    security(("sentin8:ai:conversation:write" = [])),
    tag = "ai",
)]
pub async fn update_conversation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateConversationRequest>,
) -> Result<Json<ConversationRecord>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:conversation:write"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    if let Some(s) = &body.state {
        if !matches!(s.as_str(), "active" | "archived") {
            return Err((
                StatusCode::BAD_REQUEST,
                "state must be 'active' or 'archived'".into(),
            ));
        }
    }
    let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
    let row = sqlx::query(
        "UPDATE ai.conversations SET \
            title = COALESCE($3, title), \
            state = COALESCE($4, state), \
            updated_at = now() \
          WHERE id = $1 AND env_id = $2 RETURNING *",
    )
    .bind(id)
    .bind(env_id)
    .bind(&body.title)
    .bind(&body.state)
    .fetch_optional(&mut *tx)
    .await
    .map_err(crate::handlers::err_db_pub)?
    .ok_or((StatusCode::NOT_FOUND, "conversation not found".into()))?;
    if body.state.as_deref() == Some("archived") {
        crate::handlers::emit_event_tx(
            &mut tx,
            env_id,
            "sentin8:ai:conversation:archived",
            &serde_json::json!({ "conversation_id": id }),
        )
        .await?;
    }
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    Ok(Json(conversation_from_row(&row)))
}

// ── Messages ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MessageRecord {
    pub id: Uuid,
    pub seq: i32,
    pub role: String,
    pub content: String,
    pub tool_call_id: Option<String>,
    pub model: Option<String>,
    pub token_count: i32,
    pub created_at: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct MessagesQuery {
    #[serde(default)]
    pub target_env_id: Option<String>,
    /// Return messages with `seq > after_seq` (paging).
    #[serde(default)]
    pub after_seq: Option<i32>,
}

/// `GET /v1/conversations/{id}/messages` - ordered history.
#[utoipa::path(
    get,
    operation_id = "ai.conversation.messages",
    path = "/v1/conversations/{id}/messages",
    params(("id" = Uuid, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Messages", body = Vec<MessageRecord>)),
    security(("sentin8:ai:conversation:read" = [])),
    tag = "ai",
)]
pub async fn list_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<MessagesQuery>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<MessageRecord>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:conversation:read"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    let after = q.after_seq.unwrap_or(0);
    let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
    let rows = sqlx::query(
        "SELECT id, seq, role, content, tool_call_id, model, token_count, created_at \
           FROM ai.messages WHERE conversation_id = $1 AND env_id = $2 AND seq > $3 \
          ORDER BY seq ASC LIMIT 200",
    )
    .bind(id)
    .bind(env_id)
    .bind(after)
    .fetch_all(&mut *tx)
    .await
    .map_err(crate::handlers::err_db_pub)?;
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    Ok(Json(
        rows.iter()
            .map(|r| MessageRecord {
                id: r.get("id"),
                seq: r.get("seq"),
                role: r.get("role"),
                content: r.get("content"),
                tool_call_id: r.get("tool_call_id"),
                model: r.get("model"),
                token_count: r.get("token_count"),
                created_at: r
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
            })
            .collect(),
    ))
}

// ── Turns (the agent loop) ─────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PostTurnRequest {
    /// The user's message for this turn.
    pub text: String,
    /// Client-supplied turn id - a retried turn returns the stored answer
    /// instead of appending a duplicate.
    #[serde(default)]
    pub turn_id: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TurnResponse {
    pub run_id: Uuid,
    pub conversation_id: Uuid,
    pub turn: i32,
    pub stop_reason: String,
    pub assistant_message: Option<MessageRecord>,
    /// Set when the turn paused for approval.
    pub approval_id: Option<Uuid>,
    pub iterations: i32,
    pub input_tokens: i64,
    pub output_tokens: i64,
}

/// `POST /v1/conversations/{id}/turns` - run one bounded agent turn.
///
/// The loop: assemble context → provider → tool calls (gateway) → tool
/// results → provider, until the model stops or a guard trips. Every guard
/// is recorded on the run; every message commits with the run update.
#[allow(clippy::too_many_lines)]
#[utoipa::path(
    post,
    operation_id = "ai.agent.turn",
    path = "/v1/conversations/{id}/turns",
    request_body = PostTurnRequest,
    params(("id" = Uuid, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Turn completed", body = TurnResponse)),
    security(("sentin8:ai:agent:run" = [])),
    tag = "ai",
)]
pub async fn post_turn(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(conversation_id): Path<Uuid>,
    Json(body): Json<PostTurnRequest>,
) -> Result<Json<TurnResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:agent:run"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    if body.text.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "text is required".into()));
    }
    // The caller's raw bearer - forwarded (never re-minted) to an
    // `http_action` owner so the owner re-authorizes the real user.
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let turn_id = body
        .turn_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Loop inputs, bound from the agent once the run opens (declared here,
    // assigned exactly once inside the setup transaction, read by the loop).
    let agent_system_text: String;
    let agent_model: String;
    let agent_model_fallback: Option<String>;
    let agent_temperature: Option<f64>;
    let agent_prompt_name: String;
    let allowed: Vec<tools::ToolSpec>;
    let policy: turn::TurnPolicy;

    // Open the run. Turn serialisation is structural, not advisory: the
    // `UNIQUE (conversation_id, turn)` index on ai.runs rejects a concurrent
    // duplicate with 23505, so two simultaneous turns cannot interleave seqs
    // and no lock lifecycle exists to get wrong (the review's P1 finding).
    let turn_no;
    let run_id: Uuid;
    {
        let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
        // Idempotent turn replay first: a stored user message with this
        // turn_id means the turn already ran - return its answer.
        let existing_run: Option<(Uuid, i32)> = sqlx::query_as(
            "SELECT r.id, r.turn FROM ai.runs r \
               JOIN ai.messages m ON m.conversation_id = r.conversation_id AND m.run_id = r.id \
              WHERE r.conversation_id = $1 AND m.turn_id = $2 AND m.role = 'user' LIMIT 1",
        )
        .bind(conversation_id)
        .bind(&turn_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(crate::handlers::err_db_pub)?;
        if let Some((rid, tno)) = existing_run {
            let resp = replay_turn(&state, &mut tx, conversation_id, rid, tno).await?;
            tx.commit().await.map_err(crate::handlers::err_db_pub)?;
            return Ok(Json(resp));
        }

        let conv = sqlx::query(
            "SELECT id, agent_id, state, turn_count FROM ai.conversations \
              WHERE id = $1 AND env_id = $2",
        )
        .bind(conversation_id)
        .bind(env_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(crate::handlers::err_db_pub)?
        .ok_or((StatusCode::NOT_FOUND, "conversation not found".into()))?;
        if conv.get::<String, _>("state") != "active" {
            return Err((StatusCode::CONFLICT, "conversation is archived".into()));
        }
        let agent_id: Option<Uuid> = conv.get("agent_id");
        let agent_id = agent_id.ok_or((
            StatusCode::CONFLICT,
            "conversation has no agent bound".into(),
        ))?;
        let next_turn_no: i32 = conv.get::<i32, _>("turn_count") + 1;

        // Input moderation on the user's turn text (ai DESIGN.md §5): the
        // same chain /v1/chat runs, BEFORE any provider spend.
        {
            let rules = crate::safety::load_env_rules(&mut tx, env_id)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
            if let Err(reason) = crate::safety::run_input_filters(&rules, &body.text) {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("input blocked by safety filter: {reason}"),
                ));
            }
        }

        // Bind agent + policy + prompt once; the loop re-reads nothing.
        let binding = turn::load_agent_binding(&mut tx, env_id, agent_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
            .ok_or((StatusCode::CONFLICT, "bound agent is not active".into()))?;
        let bound_policy = turn::load_policy(&mut tx, env_id, &binding.policy_name)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let prompt = crate::handlers::resolve_prompt_pub(
            &mut tx,
            env_id,
            &binding.prompt_name,
            binding.prompt_version,
        )
        .await?;
        let scopes = scopes_of(&a);
        let mut bound_tools = tools::load_agent_tools(&mut tx, env_id, agent_id, &scopes)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        bound_tools.retain(|t| {
            bound_policy.allowed_tool_classes.contains(&t.side_effect)
        });
        // Hoisted loop inputs: the loop runs in its own transactions, so the
        // agent's model/prompt/temperature and the scope-filtered allowlist
        // travel as owned values.
        agent_system_text = prompt.system_text.clone();
        agent_model = prompt.model_primary.clone();
        agent_model_fallback = prompt.model_fallback.clone();
        agent_temperature = prompt.temperature;
        agent_prompt_name = binding.prompt_name.clone();
        policy = bound_policy;
        allowed = bound_tools;

        // The run's identity: the caller's jti is recorded so a single run is
        // traceable and revocable, and the audit chain carries the claims
        // (ai DESIGN.md §5 "Agent identity"). AI requests no new token here -
        // the run executes under the CALLER's token, whose jti is below.
        let jti = a.claims.jti.clone();
        run_id = sqlx::query_scalar(
            "INSERT INTO ai.runs (conversation_id, turn, agent_token_jti, env_id) \
             VALUES ($1,$2,$3,$4) RETURNING id",
        )
        .bind(conversation_id)
        .bind(next_turn_no)
        .bind(&jti)
        .bind(env_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match e {
            // 23505 = a concurrent turn already claimed this number.
            sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => (
                StatusCode::CONFLICT,
                "another turn is running on this conversation".into(),
            ),
            other => crate::handlers::err_db_pub(other),
        })?;
        turn_no = next_turn_no;

        let user_msg = turn::user_message(body.text.clone());
        turn::append_message(
            &mut tx,
            conversation_id,
            env_id,
            &user_msg,
            None,
            0,
            Some(&turn_id),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    }

    // Loop state. Each iteration runs in its OWN short transaction: a crash
    // loses at most the in-flight provider call, never a partial transcript.
    let deadline = std::time::Instant::now() + policy_wall_clock();
    let mut iterations = 0i32;
    let mut input_tokens = 0i64;
    let mut output_tokens = 0i64;
    let mut stop = StopReason::MaxTurns;
    let mut approval_id: Option<Uuid> = None;
    let mut last_assistant: Option<MessageRecord> = None;

    while iterations < MAX_TURNS_HARD_CAP {
        if std::time::Instant::now() >= deadline {
            stop = StopReason::Cancelled;
            break;
        }
        iterations += 1;

        // Per-iteration budget gate (ai DESIGN.md §5): charged BEFORE each
        // provider call, so a long tool chain cannot overspend a cap it
        // already crossed.
        {
            let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
            let feature = format!("agent:{agent_prompt_name}");
            if let Some(mode) = crate::handlers::check_budget_pub(&mut tx, env_id, &feature).await? {
                if mode == "reject" {
                    finalize_run(&mut tx, run_id, StopReason::Budget, iterations, input_tokens, output_tokens).await?;
                    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
                    return Err((
                        StatusCode::TOO_MANY_REQUESTS,
                        "agent token budget exhausted".into(),
                    ));
                }
            }
            tx.commit().await.map_err(crate::handlers::err_db_pub)?;
        }

        // Assemble context + build the request.
        let assembled = {
            let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
            let a2 = turn::assemble_context(&mut tx, conversation_id, 60)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
            tx.commit().await.map_err(crate::handlers::err_db_pub)?;
            a2
        };
        let mut messages = Vec::with_capacity(assembled.messages.len() + 1);
        if !agent_system_text.is_empty() {
            messages.push(ChatMessage::text("system", agent_system_text.clone()));
        }
        messages.extend(assembled.messages);
        let tool_defs: Vec<serde_json::Value> = allowed.iter().map(|t| t.definition()).collect();
        let req = turn::completion_request(
            &agent_model,
            messages,
            tool_defs.clone(),
            agent_temperature,
        );

        // Provider call (no tx held across it).
        let (primary, fallback) = crate::handlers::route_for_pub(
            &state,
            env_id,
            &agent_model,
            agent_model_fallback.as_deref(),
        )
        .await?;
        let client = reqwest::Client::new();
        let started = std::time::Instant::now();
        let resp = match state
            .router
            .complete(&client, &primary, fallback.as_deref(), &req)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "agent provider call failed");
                let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
                finalize_run(&mut tx, run_id, StopReason::Error, iterations, input_tokens, output_tokens).await?;
                tx.commit().await.map_err(crate::handlers::err_db_pub)?;
                return Err((StatusCode::BAD_GATEWAY, format!("provider failure: {e}")));
            }
        };
        input_tokens += resp.input_tokens as i64;
        output_tokens += resp.output_tokens as i64;

        // Commit this iteration: assistant message, context plan, run trace,
        // and the streaming delta event all land in one transaction.
        {
            let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
            let plan = serde_json::to_value(&turn::ContextPlan {
                offered_tools: allowed.iter().map(|t| t.name.clone()).collect(),
                ..assembled.plan
            })
            .unwrap_or_default();
            sqlx::query("UPDATE ai.runs SET context_plan = $2, iterations = $3 WHERE id = $1")
                .bind(run_id)
                .bind(&plan)
                .bind(iterations)
                .execute(&mut *tx)
                .await
                .map_err(crate::handlers::err_db_pub)?;

            // Output moderation on the assistant text (both directions, every
            // hop - ai DESIGN.md §5).
            {
                let rules = crate::safety::load_env_rules(&mut tx, env_id)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
                if let Err(reason) = crate::safety::run_output_filters(&rules, &resp.content) {
                    finalize_run(&mut tx, run_id, StopReason::Error, iterations, input_tokens, output_tokens).await?;
                    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
                    return Err((
                        StatusCode::UNPROCESSABLE_ENTITY,
                        format!("output blocked by safety filter: {reason}"),
                    ));
                }
            }

            let assistant_msg = ChatMessage {
                role: "assistant".into(),
                content: resp.content.clone(),
                tool_calls: if resp.tool_calls.is_empty() {
                    None
                } else {
                    Some(resp.tool_calls.clone())
                },
                tool_call_id: None,
            };
            turn::append_message(
                &mut tx,
                conversation_id,
                env_id,
                &assistant_msg,
                Some(&resp.model),
                (resp.input_tokens + resp.output_tokens) as i32,
                None,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

            // Trace the iteration, attributed to the run (ai DESIGN.md §3).
            crate::handlers::trace_run_tx(
                &mut tx,
                env_id,
                run_id,
                &agent_prompt_name,
                &resp.model,
                &format!("agent:{agent_prompt_name}"),
                resp.input_tokens as i64,
                resp.output_tokens as i64,
                started.elapsed().as_millis() as i32,
            )
            .await?;

            // Streamed delta (ai DESIGN.md §4.1): every iteration emits the
            // assistant text so SSE subscribers see intermediate reasoning.
            crate::handlers::emit_event_tx(
                &mut tx,
                env_id,
                "sentin8:ai:turn:delta",
                &serde_json::json!({
                    "run_id": run_id,
                    "conversation_id": conversation_id,
                    "iteration": iterations,
                    "delta": resp.content,
                    "input_tokens": resp.input_tokens,
                    "output_tokens": resp.output_tokens,
                }),
            )
            .await?;
            tx.commit().await.map_err(crate::handlers::err_db_pub)?;
        }

        if !turn::wants_tools(resp.finish_reason, &resp.tool_calls) {
            last_assistant = Some(MessageRecord {
                id: Uuid::new_v4(),
                seq: 0,
                role: "assistant".into(),
                content: resp.content.clone(),
                tool_call_id: None,
                model: Some(resp.model.clone()),
                token_count: (resp.input_tokens + resp.output_tokens) as i32,
                created_at: chrono::Utc::now().to_rfc3339(),
            });
            stop = StopReason::Completed;
            break;
        }

        // Execute each tool call; each dispatch commits its own transaction so
        // a crash preserves everything decided before it.
        let mut paused = false;
        for call in &resp.tool_calls {
            if std::time::Instant::now() >= deadline {
                stop = StopReason::Cancelled;
                paused = true;
                break;
            }
            let outcome = {
                let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
                let r = execute_one(
                    &state, &mut tx, env_id, &a, &bearer, run_id, conversation_id,
                    call, &allowed, &policy,
                )
                .await;
                let r = match r {
                    Ok(o) => Some(o),
                    Err(reason) => Some(ExecOutcome::DeniedTool(reason)),
                };
                if let Some(out) = &r {
                    // Persist the tool message in the SAME tx as the journal
                    // row, then commit both together.
                    let payload = match out {
                        ExecOutcome::Continue(v) => v.clone(),
                        ExecOutcome::Approval(_) => serde_json::Value::Null,
                        ExecOutcome::DeniedTool(reason) => {
                            serde_json::json!({ "denied": reason })
                        }
                    };
                    if !payload.is_null() {
                        let tool_msg = turn::tool_message(&call.id, &payload);
                        turn::append_message(
                            &mut tx,
                            conversation_id,
                            env_id,
                            &tool_msg,
                            None,
                            0,
                            None,
                        )
                        .await
                        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
                    }
                }
                tx.commit().await.map_err(crate::handlers::err_db_pub)?;
                r
            };
            match outcome {
                Some(ExecOutcome::Continue(_)) => {}
                Some(ExecOutcome::Approval(id)) => {
                    approval_id = Some(id);
                    stop = StopReason::AwaitingApproval;
                    paused = true;
                    break;
                }
                Some(ExecOutcome::DeniedTool(_)) | None => {}
            }
        }
        if paused {
            break;
        }
        if iterations >= MAX_TURNS_HARD_CAP {
            stop = StopReason::MaxTurns;
            break;
        }
    }

    // Close the run + roll up the conversation in one final transaction.
    {
        let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
        finalize_run(&mut tx, run_id, stop, iterations, input_tokens, output_tokens).await?;
        sqlx::query("SELECT ai.ai_conversation_touch($1, $2, $3)")
            .bind(conversation_id)
            .bind(input_tokens + output_tokens)
            .bind(0.0f64)
            .execute(&mut *tx)
            .await
            .map_err(crate::handlers::err_db_pub)?;
        if last_assistant.is_none() && stop != StopReason::AwaitingApproval {
            if let Some(m) = fetch_last_assistant(&mut tx, conversation_id).await? {
                last_assistant = Some(m);
            }
        }
        crate::handlers::emit_event_tx(
            &mut tx,
            env_id,
            "sentin8:ai:run:completed",
            &serde_json::json!({
                "run_id": run_id,
                "conversation_id": conversation_id,
                "stop_reason": stop.as_str(),
            }),
        )
        .await?;
        // Audit chain from CLAIMS (ai DESIGN.md §5): the act chain is the
        // caller's jti + sub, not a hand-built array.
        audit_run(&mut tx, env_id, run_id, conversation_id, stop, &a).await;
        tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    }

    Ok(Json(TurnResponse {
        run_id,
        conversation_id,
        turn: turn_no,
        stop_reason: stop.as_str().to_string(),
        assistant_message: last_assistant,
        approval_id,
        iterations,
        input_tokens,
        output_tokens,
    }))
}

/// Outcome of executing one tool call inside the loop.
enum ExecOutcome {
    Continue(serde_json::Value),
    Approval(Uuid),
    /// Denied (allowlist/schema/scope/rate limit) with the model-visible
    /// reason. The loop appends it as a tool result so the model can adapt.
    DeniedTool(String),
}

/// Hard iteration ceiling. The agent POLICY bounds a normal run; this cap
/// exists so a run whose policy row is missing or misconfigured still
/// terminates (ai DESIGN.md invariant 11: every loop is bounded).
const MAX_TURNS_HARD_CAP: i32 = 32;

/// Wall-clock bound for one turn. Kept conservative: a turn runs inside the
/// caller's request, so the deadline is also the request's patience.
fn policy_wall_clock() -> std::time::Duration {
    std::time::Duration::from_secs(120)
}

/// Best-effort audit row for a closed run - the act chain from CLAIMS
/// (ai DESIGN.md §5): who ran it (sub + jti), on what conversation, and why
/// it stopped. Same-transaction discipline as the run close.
#[allow(clippy::too_many_arguments)]
async fn audit_run(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    env_id: Uuid,
    run_id: Uuid,
    conversation_id: Uuid,
    stop: StopReason,
    a: &auth::AuthContext,
) {
    let _ = sqlx::query(
        "INSERT INTO audit_journal (id, env_id, action, details) VALUES ($1,$2,$3,$4)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(env_id)
    .bind("agent.run")
    .bind(serde_json::json!({
        "action": "agent.run",
        "run_id": run_id,
        "conversation_id": conversation_id,
        "stop_reason": stop.as_str(),
        "act": {
            "sub": a.claims.sub,
            "jti": a.claims.jti,
            "email": a.claims.email,
            "env_id": a.claims.env_id,
        },
    }))
    .execute(&mut **tx)
    .await;
}

/// Validate, authorize, and dispatch one tool call, journalling it.
#[allow(clippy::too_many_arguments)]
async fn execute_one(
    state: &AppState,
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    env_id: Uuid,
    a: &auth::AuthContext,
    bearer: &str,
    run_id: Uuid,
    conversation_id: Uuid,
    call: &ToolCall,
    allowed: &[tools::ToolSpec],
    policy: &turn::TurnPolicy,
) -> Result<ExecOutcome, String> {
    let started = std::time::Instant::now();

    // Must be in the allowlist offered to the model (the row below is
    // authoritative; this check rejects a name the model invented).
    if !allowed.iter().any(|t| t.name == call.name) {
        return Err(format!(
            "tool '{}' is not in this agent's allowlist",
            call.name
        ));
    }

    // Re-load the row so a disabled/deleted tool cannot be reached from a
    // stale definition list.
    let spec = tools::load_tool(tx, env_id, &call.name)
        .await?
        .filter(|s| s.enabled)
        .ok_or_else(|| format!("tool '{}' is not available", call.name))?;

    // Rate limit (ai DESIGN.md §4.2): a fixed one-minute window per
    // (env, tool). A Valkey outage degrades to the local window - never open,
    // never blocking.
    if !crate::rate_limit::admit(
        &state.config.valkey_url,
        env_id,
        &spec.name,
        spec.rate_limit_per_min,
    )
    .await
    {
        let outcome = DispatchOutcome::Denied {
            reason: "per-minute rate limit exceeded".into(),
        };
        turn::record_tool_call(
            tx,
            run_id,
            env_id,
            &outcome,
            &spec.name,
            &call.arguments,
            started.elapsed().as_millis() as u64,
        )
        .await?;
        return Err("per-minute rate limit exceeded".into());
    }

    // Schema validation.
    if let Err(e) = tools::validate_arguments(&spec.input_schema, &call.arguments) {
        let outcome = DispatchOutcome::Denied {
            reason: format!("invalid arguments: {e}"),
        };
        turn::record_tool_call(tx, run_id, env_id, &outcome, &spec.name, &call.arguments, 0).await?;
        return Err(format!("invalid arguments: {e}"));
    }

    // Policy + scope.
    if !policy.allowed_tool_classes.contains(&spec.side_effect) {
        let outcome = DispatchOutcome::Denied {
            reason: format!("side effect '{}' is not allowed by policy", spec.side_effect),
        };
        turn::record_tool_call(tx, run_id, env_id, &outcome, &spec.name, &call.arguments, 0).await?;
        return Err(format!("side effect '{}' not allowed", spec.side_effect));
    }
    if !tools::scope_admits(&scopes_of(a), &spec.required_scope) {
        let outcome = DispatchOutcome::Denied {
            reason: "caller lacks the tool's required permission".into(),
        };
        turn::record_tool_call(tx, run_id, env_id, &outcome, &spec.name, &call.arguments, 0).await?;
        return Err("caller lacks the tool's required permission".into());
    }

    // Approval pause for irreversible / confirmation-required tools.
    if spec.needs_approval() || policy.confirmation_classes.contains(&spec.side_effect) {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO ai.approvals (run_id, conversation_id, tool_name, arguments, env_id) \
             VALUES ($1,$2,$3,$4,$5) RETURNING id",
        )
        .bind(run_id)
        .bind(conversation_id)
        .bind(&spec.name)
        .bind(&call.arguments)
        .bind(env_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| format!("create approval: {e}"))?;
        let outcome = DispatchOutcome::AwaitingApproval { approval_id: id };
        turn::record_tool_call(
            tx,
            run_id,
            env_id,
            &outcome,
            &spec.name,
            &call.arguments,
            started.elapsed().as_millis() as u64,
        )
        .await?;
        return Ok(ExecOutcome::Approval(id));
    }

    // Dispatch. Authority rides the CALLER's bearer: the owner re-verifies
    // it and applies its own Shield gate, so a tool can never exceed what
    // the requesting user could do directly (ai DESIGN.md §4.2).
    let key = crate::agent_gateway::dispatch_key(run_id, Uuid::new_v4());
    let d = crate::agent_gateway::Dispatch {
        state,
        env_id,
        bearer,
        correlation_id: &run_id.to_string(),
        idempotency_key: &key,
    };
    let result = crate::agent_gateway::dispatch(&d, &spec, &call.arguments).await;
    let duration = started.elapsed().as_millis() as u64;
    match result {
        Ok(v) => {
            let outcome = DispatchOutcome::Ok {
                result: v.clone(),
                duration_ms: duration,
            };
            turn::record_tool_call(tx, run_id, env_id, &outcome, &spec.name, &call.arguments, duration)
                .await?;
            Ok(ExecOutcome::Continue(v))
        }
        Err(message) => {
            let outcome = DispatchOutcome::Error {
                message: message.clone(),
                duration_ms: duration,
            };
            turn::record_tool_call(tx, run_id, env_id, &outcome, &spec.name, &call.arguments, duration)
                .await?;
            Err(message)
        }
    }
}

/// Close a run with its terminal state.
async fn finalize_run(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    run_id: Uuid,
    stop: StopReason,
    iterations: i32,
    input_tokens: i64,
    output_tokens: i64,
) -> Result<(), (StatusCode, String)> {
    sqlx::query(
        "UPDATE ai.runs SET stop_reason = $2, iterations = $3, \
            input_tokens = $4, output_tokens = $5, updated_at = now() WHERE id = $1",
    )
    .bind(run_id)
    .bind(stop.as_str())
    .bind(iterations)
    .bind(input_tokens)
    .bind(output_tokens)
    .execute(&mut **tx)
    .await
    .map_err(crate::handlers::err_db_pub)?;
    Ok(())
}

async fn fetch_last_assistant(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    conversation_id: Uuid,
) -> Result<Option<MessageRecord>, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT id, seq, role, content, tool_call_id, model, token_count, created_at \
           FROM ai.messages WHERE conversation_id = $1 AND role = 'assistant' \
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(conversation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(crate::handlers::err_db_pub)?;
    Ok(row.map(|r| MessageRecord {
        id: r.get("id"),
        seq: r.get("seq"),
        role: r.get("role"),
        content: r.get("content"),
        tool_call_id: r.get("tool_call_id"),
        model: r.get("model"),
        token_count: r.get("token_count"),
        created_at: r
            .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
            .to_rfc3339(),
    }))
}

async fn replay_turn(
    _state: &AppState,
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    conversation_id: Uuid,
    run_id: Uuid,
    turn_no: i32,
) -> Result<TurnResponse, (StatusCode, String)> {
    let run = sqlx::query(
        "SELECT stop_reason, iterations, input_tokens, output_tokens FROM ai.runs WHERE id = $1",
    )
    .bind(run_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(crate::handlers::err_db_pub)?;
    let msg = fetch_last_assistant(tx, conversation_id).await?;
    Ok(TurnResponse {
        run_id,
        conversation_id,
        turn: turn_no,
        stop_reason: run.get::<Option<String>, _>("stop_reason").unwrap_or_default(),
        assistant_message: msg,
        approval_id: None,
        iterations: run.get("iterations"),
        input_tokens: run.get("input_tokens"),
        output_tokens: run.get("output_tokens"),
    })
}

// ── Approvals ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct DecideApprovalRequest {
    /// `approved` | `denied`.
    pub decision: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApprovalRecord {
    pub id: Uuid,
    pub run_id: Uuid,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub state: String,
    pub decided_by: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ApprovalsQuery {
    #[serde(default)]
    pub target_env_id: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

/// `GET /v1/approvals` - pending approvals in the env.
#[utoipa::path(
    get,
    operation_id = "ai.approval.list",
    path = "/v1/approvals",
    params(("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Approvals", body = Vec<ApprovalRecord>)),
    security(("sentin8:ai:agent:approve" = [])),
    tag = "ai",
)]
pub async fn list_approvals(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ApprovalsQuery>,
) -> Result<Json<Vec<ApprovalRecord>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:agent:approve"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    let wanted = q.state.unwrap_or_else(|| "pending".into());
    let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
    let rows = sqlx::query(
        "SELECT id, run_id, tool_name, arguments, state, decided_by, created_at \
           FROM ai.approvals WHERE env_id = $1 AND state = $2 ORDER BY created_at DESC LIMIT 100",
    )
    .bind(env_id)
    .bind(&wanted)
    .fetch_all(&mut *tx)
    .await
    .map_err(crate::handlers::err_db_pub)?;
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    Ok(Json(
        rows.iter()
            .map(|r| ApprovalRecord {
                id: r.get("id"),
                run_id: r.get("run_id"),
                tool_name: r.get("tool_name"),
                arguments: r.get("arguments"),
                state: r.get("state"),
                decided_by: r.get("decided_by"),
                created_at: r
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
            })
            .collect(),
    ))
}

/// `POST /v1/approvals/{id}/decide` - approve or deny a paused action.
#[utoipa::path(
    post,
    operation_id = "ai.approval.decide",
    path = "/v1/approvals/{id}/decide",
    request_body = DecideApprovalRequest,
    params(("id" = Uuid, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Decision recorded", body = ApprovalRecord)),
    security(("sentin8:ai:agent:approve" = [])),
    tag = "ai",
)]
pub async fn decide_approval(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
    Json(body): Json<DecideApprovalRequest>,
) -> Result<Json<ApprovalRecord>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:agent:approve"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    if !matches!(body.decision.as_str(), "approved" | "denied") {
        return Err((
            StatusCode::BAD_REQUEST,
            "decision must be 'approved' or 'denied'".into(),
        ));
    }
    let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
    let row = sqlx::query(
        "UPDATE ai.approvals SET state = $2, decided_by = $3, decided_at = now() \
          WHERE id = $1 AND env_id = $4 AND state = 'pending' RETURNING *",
    )
    .bind(id)
    .bind(&body.decision)
    .bind(&a.claims.sub)
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(crate::handlers::err_db_pub)?
    .ok_or((
        StatusCode::NOT_FOUND,
        "pending approval not found".into(),
    ))?;

    // The decision itself commits FIRST: an approved approval is never
    // re-decidable, whatever the tool dispatch then does.
    let run_id: Uuid = row.get("run_id");
    let tool_name: String = row.get("tool_name");
    let arguments: serde_json::Value = row.get("arguments");
    let conversation_id: Uuid = row.get("conversation_id");

    if body.decision == "denied" {
        // A denial fails the run. The model never re-drives a denied action -
        // the caller starts a new turn if it wants to try something else.
        sqlx::query("UPDATE ai.runs SET stop_reason = 'error', updated_at = now() WHERE id = $1")
            .bind(run_id)
            .execute(&mut *tx)
            .await
            .map_err(crate::handlers::err_db_pub)?;
        crate::handlers::emit_event_tx(
            &mut tx,
            env_id,
            "sentin8:ai:approval:decided",
            &serde_json::json!({ "approval_id": id, "decision": "denied", "run_id": run_id }),
        )
        .await?;
        tx.commit().await.map_err(crate::handlers::err_db_pub)?;
        return Ok(Json(ApprovalRecord {
            id: row.get("id"),
            run_id,
            tool_name,
            arguments,
            state: row.get("state"),
            decided_by: row.get("decided_by"),
            created_at: row
                .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                .to_rfc3339(),
        }));
    }

    // APPROVED: the run reopens, and the paused tool executes NOW under the
    // APPROVER's authorization (ai DESIGN.md §3: "a resumed approval opens
    // the next iteration of the same run"). The gateway re-validates the
    // schema and the approver's scope - approval never bypasses the gates.
    sqlx::query("UPDATE ai.runs SET stop_reason = NULL, updated_at = now() WHERE id = $1")
        .bind(run_id)
        .execute(&mut *tx)
        .await
        .map_err(crate::handlers::err_db_pub)?;
    crate::handlers::emit_event_tx(
        &mut tx,
        env_id,
        "sentin8:ai:approval:decided",
        &serde_json::json!({ "approval_id": id, "decision": "approved", "run_id": run_id }),
    )
    .await?;
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;

    // Load the tool and gate it exactly as the loop does, then dispatch.
    let mut exec_tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
    let spec = match tools::load_tool(&mut exec_tx, env_id, &tool_name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    {
        Some(t) if t.enabled => t,
        _ => {
            return Err((
                StatusCode::CONFLICT,
                "the approved tool is no longer available".into(),
            ))
        }
    };
    if let Err(e) = tools::validate_arguments(&spec.input_schema, &arguments) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("approved arguments no longer conform: {e}"),
        ));
    }
    if !tools::scope_admits(&scopes_of(&a), &spec.required_scope) {
        return Err((
            StatusCode::FORBIDDEN,
            "approver lacks the tool's required permission".into(),
        ));
    }
    if !crate::rate_limit::admit(
        &state.config.valkey_url,
        env_id,
        &spec.name,
        spec.rate_limit_per_min,
    )
    .await
    {
        return Err((StatusCode::TOO_MANY_REQUESTS, "tool rate limit exceeded".into()));
    }

    let started = std::time::Instant::now();
    let key = crate::agent_gateway::dispatch_key(run_id, id);
    let d = crate::agent_gateway::Dispatch {
        state: &state,
        env_id,
        bearer: &headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        correlation_id: &run_id.to_string(),
        idempotency_key: &key,
    };
    let dispatch_result = crate::agent_gateway::dispatch(&d, &spec, &arguments).await;
    let duration = started.elapsed().as_millis() as u64;
    let outcome = match dispatch_result {
        Ok(result) => crate::tools::DispatchOutcome::Ok {
            result: result.clone(),
            duration_ms: duration,
        },
        Err(message) => crate::tools::DispatchOutcome::Error {
            message,
            duration_ms: duration,
        },
    };
    let dispatch_ok = matches!(outcome, crate::tools::DispatchOutcome::Ok { .. });
    turn::record_tool_call(
        &mut exec_tx,
        run_id,
        env_id,
        &outcome,
        &spec.name,
        &arguments,
        duration,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if dispatch_ok {
        // The tool result re-enters the transcript (sanitized by the gateway)
        // so the NEXT turn can reason about it.
        let payload = match &outcome {
            crate::tools::DispatchOutcome::Ok { result, .. } => result.clone(),
            _ => serde_json::Value::Null,
        };
        let tool_msg = turn::tool_message(&id.to_string(), &payload);
        turn::append_message(&mut exec_tx, conversation_id, env_id, &tool_msg, None, 0, None)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }
    // Re-close the run: completed on success, error on failure. Either way the
    // caller starts the next turn explicitly.
    let final_state = if dispatch_ok { "completed" } else { "error" };
    sqlx::query("UPDATE ai.runs SET stop_reason = $2, updated_at = now() WHERE id = $1")
        .bind(run_id)
        .bind(final_state)
        .execute(&mut *exec_tx)
        .await
        .map_err(crate::handlers::err_db_pub)?;
    exec_tx
        .commit()
        .await
        .map_err(crate::handlers::err_db_pub)?;

    Ok(Json(ApprovalRecord {
        id: row.get("id"),
        run_id,
        tool_name: row.get("tool_name"),
        arguments: row.get("arguments"),
        state: row.get("state"),
        decided_by: row.get("decided_by"),
        created_at: row
            .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
            .to_rfc3339(),
    }))
}

// ── Tools CRUD ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpsertToolRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub input_schema: Option<serde_json::Value>,
    pub kind: String,
    #[serde(default)]
    pub target: serde_json::Value,
    #[serde(default)]
    pub required_scope: String,
    #[serde(default = "default_side_effect")]
    pub side_effect: String,
    #[serde(default)]
    pub requires_confirmation: bool,
    #[serde(default)]
    pub rate_limit_per_min: i32,
    #[serde(default = "default_timeout")]
    pub timeout_ms: i32,
    #[serde(default = "default_cap")]
    pub max_response_bytes: i32,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_side_effect() -> String {
    "read".into()
}
fn default_timeout() -> i32 {
    30000
}
fn default_cap() -> i32 {
    65536
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ToolRecord {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub kind: String,
    pub target: serde_json::Value,
    pub required_scope: String,
    pub side_effect: String,
    pub requires_confirmation: bool,
    pub enabled: bool,
}

fn tool_record(s: &tools::ToolSpec) -> ToolRecord {
    ToolRecord {
        id: s.id,
        name: s.name.clone(),
        description: s.description.clone(),
        input_schema: s.input_schema.clone(),
        kind: s.kind.clone(),
        target: s.target.clone(),
        required_scope: s.required_scope.clone(),
        side_effect: s.side_effect.clone(),
        requires_confirmation: s.requires_confirmation,
        enabled: s.enabled,
    }
}

fn validate_tool_body(b: &UpsertToolRequest) -> Result<(), (StatusCode, String)> {
    if b.name.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "tool name is required".into()));
    }
    if !matches!(
        b.kind.as_str(),
        "http_action" | "flow_workflow" | "func_module" | "builtin"
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            "kind must be http_action|flow_workflow|func_module|builtin".into(),
        ));
    }
    if !matches!(b.side_effect.as_str(), "read" | "write" | "irreversible") {
        return Err((
            StatusCode::BAD_REQUEST,
            "side_effect must be read|write|irreversible".into(),
        ));
    }
    Ok(())
}

/// `PUT /v1/tools/{name}` - create or update a tenant tool.
#[utoipa::path(
    put,
    operation_id = "ai.tool.upsert",
    path = "/v1/tools/{name}",
    request_body = UpsertToolRequest,
    params(("name" = String, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Tool saved", body = ToolRecord)),
    security(("sentin8:ai:tool:write" = [])),
    tag = "ai",
)]
pub async fn put_tool(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(name): Path<String>,
    Json(body): Json<UpsertToolRequest>,
) -> Result<Json<ToolRecord>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:tool:write"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    if body.name != name {
        return Err((
            StatusCode::BAD_REQUEST,
            "path name and body name must match".into(),
        ));
    }
    validate_tool_body(&body)?;
    let schema = body
        .input_schema
        .clone()
        .unwrap_or_else(|| serde_json::json!({"type":"object","properties":{}}));

    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, env_id).await?;
    let spec = sqlx::query(
        "INSERT INTO ai.tools \
         (name, description, input_schema, kind, target, required_scope, side_effect, \
          requires_confirmation, rate_limit_per_min, timeout_ms, max_response_bytes, enabled, env_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) \
         ON CONFLICT (env_id, name) DO UPDATE SET \
           description = $2, input_schema = $3, kind = $4, target = $5, required_scope = $6, \
           side_effect = $7, requires_confirmation = $8, rate_limit_per_min = $9, \
           timeout_ms = $10, max_response_bytes = $11, enabled = $12, updated_at = now() \
         RETURNING id, name, description, input_schema, kind, target, required_scope, \
                   side_effect, requires_confirmation, rate_limit_per_min, timeout_ms, \
                   max_response_bytes, enabled",
    )
    .bind(&body.name)
    .bind(&body.description)
    .bind(&schema)
    .bind(&body.kind)
    .bind(&body.target)
    .bind(&body.required_scope)
    .bind(&body.side_effect)
    .bind(body.requires_confirmation)
    .bind(body.rate_limit_per_min)
    .bind(body.timeout_ms)
    .bind(body.max_response_bytes)
    .bind(body.enabled)
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(crate::handlers::err_db_pub)?;
    crate::handlers::emit_event_tx(
        &mut tx,
        env_id,
        "sentin8:ai:tool:updated",
        &serde_json::json!({ "tool": body.name }),
    )
    .await?;
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    Ok(Json(ToolRecord {
        id: spec.get("id"),
        name: spec.get("name"),
        description: spec.get("description"),
        input_schema: spec.get("input_schema"),
        kind: spec.get("kind"),
        target: spec.get("target"),
        required_scope: spec.get("required_scope"),
        side_effect: spec.get("side_effect"),
        requires_confirmation: spec.get("requires_confirmation"),
        enabled: spec.get("enabled"),
    }))
}

/// `GET /v1/tools` - the caller's permission-admitted tool catalogue.
#[utoipa::path(
    get,
    operation_id = "ai.tool.list",
    path = "/v1/tools",
    params(("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Tools", body = Vec<ToolRecord>)),
    security(("sentin8:ai:tool:read" = [])),
    tag = "ai",
)]
pub async fn list_tools(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<Vec<ToolRecord>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:tool:read"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    let scopes = scopes_of(&a);
    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, env_id).await?;
    let rows = sqlx::query(
        "SELECT id, name, description, input_schema, kind, target, required_scope, \
                side_effect, requires_confirmation, rate_limit_per_min, timeout_ms, \
                max_response_bytes, enabled \
           FROM ai.tools WHERE env_id = $1 AND enabled = true ORDER BY name",
    )
    .bind(env_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(crate::handlers::err_db_pub)?;
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;

    let specs: Vec<tools::ToolSpec> = rows
        .iter()
        .map(|r| tools::ToolSpec {
            id: r.get("id"),
            name: r.get("name"),
            description: r.get("description"),
            input_schema: r.get("input_schema"),
            kind: r.get("kind"),
            target: r.get("target"),
            required_scope: r.get("required_scope"),
            side_effect: r.get("side_effect"),
            requires_confirmation: r.get("requires_confirmation"),
            rate_limit_per_min: r.get("rate_limit_per_min"),
            timeout_ms: r.get("timeout_ms"),
            max_response_bytes: r.get("max_response_bytes"),
            enabled: r.get("enabled"),
        })
        // Discovery is scope-filtered: a UI never shows a tool the caller
        // cannot actually use.
        .filter(|t| tools::scope_admits(&scopes, &t.required_scope))
        .collect();

    Ok(Json(specs.iter().map(tool_record).collect()))
}

/// `DELETE /v1/tools/{name}` - remove a tool.
#[utoipa::path(
    delete,
    operation_id = "ai.tool.delete",
    path = "/v1/tools/{name}",
    params(("name" = String, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 204, description = "Tool removed")),
    security(("sentin8:ai:tool:write" = [])),
    tag = "ai",
)]
pub async fn delete_tool(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:tool:write"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, env_id).await?;
    let n = sqlx::query("DELETE FROM ai.tools WHERE env_id = $1 AND name = $2")
        .bind(env_id)
        .bind(&name)
        .execute(&mut *tx)
        .await
        .map_err(crate::handlers::err_db_pub)?
        .rows_affected();
    if n == 0 {
        return Err((StatusCode::NOT_FOUND, "tool not found".into()));
    }
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Agents CRUD ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpsertAgentRequest {
    pub prompt_name: String,
    #[serde(default)]
    pub prompt_version: Option<i32>,
    #[serde(default = "default_policy_name")]
    pub policy_name: String,
    /// Tool names to bind. Unknown names are rejected (fail-closed).
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default = "default_active")]
    pub status: String,
}

fn default_policy_name() -> String {
    "default".into()
}
fn default_active() -> String {
    "active".into()
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AgentRecord {
    pub id: Uuid,
    pub name: String,
    pub prompt_name: String,
    pub prompt_version: Option<i32>,
    pub policy_name: String,
    pub tools: Vec<String>,
    pub status: String,
}

/// `PUT /v1/agents/{name}` - create or update an agent and its tool set.
#[utoipa::path(
    put,
    operation_id = "ai.agent.upsert",
    path = "/v1/agents/{name}",
    request_body = UpsertAgentRequest,
    params(("name" = String, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Agent saved", body = AgentRecord)),
    security(("sentin8:ai:agent:write" = [])),
    tag = "ai",
)]
pub async fn put_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(name): Path<String>,
    Json(body): Json<UpsertAgentRequest>,
) -> Result<Json<AgentRecord>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:agent:write"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    if !matches!(body.status.as_str(), "active" | "disabled") {
        return Err((
            StatusCode::BAD_REQUEST,
            "status must be active|disabled".into(),
        ));
    }
    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, env_id).await?;

    // Tool names must resolve - an agent cannot reference a ghost tool.
    let mut tool_ids = Vec::with_capacity(body.tools.len());
    for t in &body.tools {
        let id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM ai.tools WHERE env_id = $1 AND name = $2")
                .bind(env_id)
                .bind(t)
                .fetch_optional(&mut *tx)
                .await
                .map_err(crate::handlers::err_db_pub)?;
        let id = id.ok_or((
            StatusCode::BAD_REQUEST,
            format!("tool '{t}' does not exist"),
        ))?;
        tool_ids.push(id);
    }

    let agent_id: Uuid = sqlx::query_scalar(
        "INSERT INTO ai.agents (name, prompt_name, prompt_version, policy_name, status, env_id) \
         VALUES ($1,$2,$3,$4,$5,$6) \
         ON CONFLICT (env_id, name) DO UPDATE SET \
           prompt_name = $2, prompt_version = $3, policy_name = $4, status = $5, updated_at = now() \
         RETURNING id",
    )
    .bind(&name)
    .bind(&body.prompt_name)
    .bind(body.prompt_version)
    .bind(&body.policy_name)
    .bind(&body.status)
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(crate::handlers::err_db_pub)?;

    sqlx::query("DELETE FROM ai.agent_tools WHERE agent_id = $1")
        .bind(agent_id)
        .execute(&mut *tx)
        .await
        .map_err(crate::handlers::err_db_pub)?;
    for tool_id in &tool_ids {
        sqlx::query(
            "INSERT INTO ai.agent_tools (agent_id, tool_id, env_id) VALUES ($1,$2,$3) \
             ON CONFLICT DO NOTHING",
        )
        .bind(agent_id)
        .bind(tool_id)
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(crate::handlers::err_db_pub)?;
    }

    crate::handlers::emit_event_tx(
        &mut tx,
        env_id,
        "sentin8:ai:agent:updated",
        &serde_json::json!({ "agent": name }),
    )
    .await?;
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;

    Ok(Json(AgentRecord {
        id: agent_id,
        name,
        prompt_name: body.prompt_name,
        prompt_version: body.prompt_version,
        policy_name: body.policy_name,
        tools: body.tools,
        status: body.status,
    }))
}

/// `GET /v1/agents` - list agents.
#[utoipa::path(
    get,
    operation_id = "ai.agent.list",
    path = "/v1/agents",
    params(("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Agents", body = Vec<AgentRecord>)),
    security(("sentin8:ai:agent:read" = [])),
    tag = "ai",
)]
pub async fn list_agents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<Vec<AgentRecord>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:agent:read"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, env_id).await?;
    let rows = sqlx::query(
        "SELECT a.id, a.name, a.prompt_name, a.prompt_version, a.policy_name, a.status, \
                COALESCE(array_agg(t.name ORDER BY t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS tools \
           FROM ai.agents a \
           LEFT JOIN ai.agent_tools at ON at.agent_id = a.id \
           LEFT JOIN ai.tools t ON t.id = at.tool_id \
          WHERE a.env_id = $1 GROUP BY a.id ORDER BY a.name",
    )
    .bind(env_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(crate::handlers::err_db_pub)?;
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    Ok(Json(
        rows.iter()
            .map(|r| AgentRecord {
                id: r.get("id"),
                name: r.get("name"),
                prompt_name: r.get("prompt_name"),
                prompt_version: r.get("prompt_version"),
                policy_name: r.get("policy_name"),
                tools: r.get::<Vec<String>, _>("tools"),
                status: r.get("status"),
            })
            .collect(),
    ))
}

/// `DELETE /v1/agents/{name}` - remove an agent.
#[utoipa::path(
    delete,
    operation_id = "ai.agent.delete",
    path = "/v1/agents/{name}",
    params(("name" = String, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 204, description = "Agent removed")),
    security(("sentin8:ai:agent:write" = [])),
    tag = "ai",
)]
pub async fn delete_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:agent:write"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, env_id).await?;
    let n = sqlx::query("DELETE FROM ai.agents WHERE env_id = $1 AND name = $2")
        .bind(env_id)
        .bind(&name)
        .execute(&mut *tx)
        .await
        .map_err(crate::handlers::err_db_pub)?
        .rows_affected();
    if n == 0 {
        return Err((StatusCode::NOT_FOUND, "agent not found".into()));
    }
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Agent policies ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpsertPolicyRequest {
    #[serde(default)]
    pub allowed_models: Vec<String>,
    #[serde(default = "default_max_turns")]
    pub max_turns: i32,
    #[serde(default = "default_max_tokens")]
    pub max_tokens_per_turn: i32,
    #[serde(default = "default_tool_classes")]
    pub allowed_tool_classes: Vec<String>,
    #[serde(default = "default_confirm_classes")]
    pub confirmation_classes: Vec<String>,
    #[serde(default = "default_retention")]
    pub retention_days: i32,
}

fn default_max_turns() -> i32 {
    8
}
fn default_max_tokens() -> i32 {
    8192
}
fn default_tool_classes() -> Vec<String> {
    vec!["read".into(), "write".into()]
}
fn default_confirm_classes() -> Vec<String> {
    vec!["irreversible".into()]
}
fn default_retention() -> i32 {
    90
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PolicyRecord {
    pub name: String,
    pub allowed_models: Vec<String>,
    pub max_turns: i32,
    pub max_tokens_per_turn: i32,
    pub allowed_tool_classes: Vec<String>,
    pub confirmation_classes: Vec<String>,
    pub retention_days: i32,
}

/// `PUT /v1/agent-policies/{name}` - upsert an agent policy.
#[utoipa::path(
    put,
    operation_id = "ai.agent_policy.upsert",
    path = "/v1/agent-policies/{name}",
    request_body = UpsertPolicyRequest,
    params(("name" = String, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Policy saved", body = PolicyRecord)),
    security(("sentin8:ai:agent:write" = [])),
    tag = "ai",
)]
pub async fn put_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(name): Path<String>,
    Json(body): Json<UpsertPolicyRequest>,
) -> Result<Json<PolicyRecord>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:agent:write"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    if body.max_turns <= 0 || body.max_tokens_per_turn <= 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "max_turns and max_tokens_per_turn must be positive".into(),
        ));
    }
    for c in &body.allowed_tool_classes {
        if !matches!(c.as_str(), "read" | "write" | "irreversible") {
            return Err((
                StatusCode::BAD_REQUEST,
                "allowed_tool_classes values must be read|write|irreversible".into(),
            ));
        }
    }
    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, env_id).await?;
    sqlx::query(
        "INSERT INTO ai.agent_policies \
         (name, allowed_models, max_turns, max_tokens_per_turn, allowed_tool_classes, \
          confirmation_classes, retention_days, env_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
         ON CONFLICT (env_id, name) DO UPDATE SET \
           allowed_models = $2, max_turns = $3, max_tokens_per_turn = $4, \
           allowed_tool_classes = $5, confirmation_classes = $6, retention_days = $7, updated_at = now()",
    )
    .bind(&name)
    .bind(serde_json::json!(body.allowed_models))
    .bind(body.max_turns)
    .bind(body.max_tokens_per_turn)
    .bind(serde_json::json!(body.allowed_tool_classes))
    .bind(serde_json::json!(body.confirmation_classes))
    .bind(body.retention_days)
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(crate::handlers::err_db_pub)?;
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    Ok(Json(PolicyRecord {
        name,
        allowed_models: body.allowed_models,
        max_turns: body.max_turns,
        max_tokens_per_turn: body.max_tokens_per_turn,
        allowed_tool_classes: body.allowed_tool_classes,
        confirmation_classes: body.confirmation_classes,
        retention_days: body.retention_days,
    }))
}

/// `GET /v1/agent-policies` - list policies.
#[utoipa::path(
    get,
    operation_id = "ai.agent_policy.list",
    path = "/v1/agent-policies",
    params(("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Policies", body = Vec<PolicyRecord>)),
    security(("sentin8:ai:agent:read" = [])),
    tag = "ai",
)]
pub async fn list_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<Vec<PolicyRecord>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:agent:read"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, env_id).await?;
    let rows = sqlx::query(
        "SELECT name, allowed_models, max_turns, max_tokens_per_turn, \
                allowed_tool_classes, confirmation_classes, retention_days \
           FROM ai.agent_policies WHERE env_id = $1 ORDER BY name",
    )
    .bind(env_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(crate::handlers::err_db_pub)?;
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    Ok(Json(
        rows.iter()
            .map(|r| PolicyRecord {
                name: r.get("name"),
                allowed_models: string_vec(r.get("allowed_models")),
                max_turns: r.get("max_turns"),
                max_tokens_per_turn: r.get("max_tokens_per_turn"),
                allowed_tool_classes: string_vec(r.get("allowed_tool_classes")),
                confirmation_classes: string_vec(r.get("confirmation_classes")),
                retention_days: r.get("retention_days"),
            })
            .collect(),
    ))
}

fn string_vec(v: serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

// ── Runs ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RunRecord {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub turn: i32,
    pub stop_reason: Option<String>,
    pub iterations: i32,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub context_plan: serde_json::Value,
    pub created_at: String,
}

/// `GET /v1/runs/{id}` - one run's record.
#[utoipa::path(
    get,
    operation_id = "ai.run.get",
    path = "/v1/runs/{id}",
    params(("id" = Uuid, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Run", body = RunRecord)),
    security(("sentin8:ai:agent:run" = [])),
    tag = "ai",
)]
pub async fn get_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<Json<RunRecord>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:agent:run"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
    let r = sqlx::query(
        "SELECT id, conversation_id, turn, stop_reason, iterations, input_tokens, \
                output_tokens, context_plan, created_at \
           FROM ai.runs WHERE id = $1 AND env_id = $2",
    )
    .bind(id)
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(crate::handlers::err_db_pub)?
    .ok_or((StatusCode::NOT_FOUND, "run not found".into()))?;
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    Ok(Json(RunRecord {
        id: r.get("id"),
        conversation_id: r.get("conversation_id"),
        turn: r.get("turn"),
        stop_reason: r.get("stop_reason"),
        iterations: r.get("iterations"),
        input_tokens: r.get("input_tokens"),
        output_tokens: r.get("output_tokens"),
        context_plan: r.get("context_plan"),
        created_at: r
            .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
            .to_rfc3339(),
    }))
}

/// `POST /v1/runs/{id}/cancel` - cancel a waiting/processing run.
#[utoipa::path(
    post,
    operation_id = "ai.run.cancel",
    path = "/v1/runs/{id}/cancel",
    params(("id" = Uuid, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 204, description = "Run cancelled")),
    security(("sentin8:ai:agent:run" = [])),
    tag = "ai",
)]
pub async fn cancel_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:agent:run"),
    )
    .await?;
    let env_id = crate::handlers::resolve_env_id_pub(&a, q.target_env_id.as_deref())?;
    let mut tx = crate::handlers::begin_agent_tx(&state.pool, env_id, &a).await?;
    let n = sqlx::query(
        "UPDATE ai.runs SET stop_reason = 'cancelled', updated_at = now() \
          WHERE id = $1 AND env_id = $2 AND stop_reason IS NULL",
    )
    .bind(id)
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(crate::handlers::err_db_pub)?
    .rows_affected();
    if n == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "no in-flight run with that id".into(),
        ));
    }
    tx.commit().await.map_err(crate::handlers::err_db_pub)?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_validation_rejects_unknown_kind_and_class() {
        let mut b = UpsertToolRequest {
            name: "t".into(),
            description: String::new(),
            input_schema: None,
            kind: "http_action".into(),
            target: serde_json::json!({}),
            required_scope: String::new(),
            side_effect: "read".into(),
            requires_confirmation: false,
            rate_limit_per_min: 0,
            timeout_ms: 30000,
            max_response_bytes: 65536,
            enabled: true,
        };
        assert!(validate_tool_body(&b).is_ok());
        b.kind = "rm_rf".into();
        assert!(validate_tool_body(&b).is_err());
        b.kind = "builtin".into();
        b.side_effect = "nuclear".into();
        assert!(validate_tool_body(&b).is_err());
    }

    #[test]
    fn policy_defaults_keep_irreversible_confirmed() {
        assert!(default_confirm_classes().contains(&"irreversible".to_string()));
        assert!(!default_tool_classes().contains(&"irreversible".to_string()));
    }

    #[test]
    fn string_vec_tolerates_non_arrays() {
        assert!(string_vec(serde_json::Value::Null).is_empty());
        assert_eq!(
            string_vec(serde_json::json!(["a", "b"])),
            vec!["a".to_string(), "b".to_string()]
        );
    }
}

// ── Internal agent step execution (Flow proxy-back, aiag-12) ──────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[allow(dead_code)]
pub struct AgentStepRequest {
    /// Step kind Flow invoked (the engine's `step_kind`).
    #[serde(default)]
    pub step_kind: String,
    pub workflow_id: Uuid,
    pub env_id: Uuid,
    pub step_name: String,
    #[serde(default)]
    pub input: serde_json::Value,
    #[serde(default)]
    pub user_data: serde_json::Value,
    #[serde(default)]
    pub step_config: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AgentStepResponse {
    pub status: String,
    pub output: Option<serde_json::Value>,
    pub error: Option<String>,
    pub next_step: Option<String>,
}

/// `POST /v1/internal/agent/execute` - the domain-step surface Sentin8:Flow
/// proxy-backs to for a legacy JSON-intent agent workflow (ai DESIGN.md
/// §4.1). The step's `step_config` names a tool; the gateway dispatches it
/// under the workflow's env with the `ai-proxy` workload identity.
#[utoipa::path(
    post,
    operation_id = "ai.agent.internal_step",
    path = "/v1/internal/agent/execute",
    request_body = AgentStepRequest,
    responses((status = 200, description = "Step executed", body = AgentStepResponse)),
    security(("sentin8:ai:agent:run" = [])),
    tag = "ai",
)]
pub async fn internal_agent_step(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AgentStepRequest>,
) -> Result<Json<AgentStepResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:agent:run"),
    )
    .await?;

    let Some(config) = body.step_config else {
        return Ok(Json(AgentStepResponse {
            status: "success".into(),
            output: None,
            error: None,
            next_step: None,
        }));
    };
    let Some(tool_name) = config.get("action").and_then(|v| v.as_str()) else {
        return Ok(Json(AgentStepResponse {
            status: "failed".into(),
            output: None,
            error: Some("agent step config has no 'action'".into()),
            next_step: None,
        }));
    };
    let arguments = config
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, body.env_id).await?;
    let spec = match tools::load_tool(&mut tx, body.env_id, tool_name).await {
        Ok(Some(s)) if s.enabled => s,
        Ok(_) => {
            return Ok(Json(AgentStepResponse {
                status: "failed".into(),
                output: None,
                error: Some(format!("tool '{tool_name}' is not available")),
                next_step: None,
            }))
        }
        Err(e) => {
            return Ok(Json(AgentStepResponse {
                status: "failed".into(),
                output: None,
                error: Some(e),
                next_step: None,
            }))
        }
    };
    if let Err(e) = tools::validate_arguments(&spec.input_schema, &arguments) {
        return Ok(Json(AgentStepResponse {
            status: "failed".into(),
            output: None,
            error: Some(format!("invalid arguments: {e}")),
            next_step: None,
        }));
    }
    let _ = tx.commit().await;

    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let key = crate::agent_gateway::dispatch_key(body.workflow_id, Uuid::new_v4());
    let d = crate::agent_gateway::Dispatch {
        state: &state,
        env_id: body.env_id,
        bearer: &bearer,
        correlation_id: &body.workflow_id.to_string(),
        idempotency_key: &key,
    };
    match crate::agent_gateway::dispatch(&d, &spec, &arguments).await {
        Ok(v) => Ok(Json(AgentStepResponse {
            status: "success".into(),
            output: Some(v),
            error: None,
            next_step: None,
        })),
        Err(e) => Ok(Json(AgentStepResponse {
            status: "failed".into(),
            output: None,
            error: Some(e),
            next_step: None,
        })),
    }
}
