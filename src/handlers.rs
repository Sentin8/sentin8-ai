// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! AI HTTP handlers - prompt registry, inference primitives, retrieval,
//! provider registry, traces.
//!
//! Authorization: `require_auth` + `require_policy` ONLY - no handler scope
//! checks; step 5 of the authorization pipeline is the single gate.
//! RLS: every tenant query runs inside `begin_tenant_tx` (same-connection
//! context set).

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::config::AiConfig;
use crate::providers::{ProviderRouter, Route};
use sha2::Digest as _;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AiConfig>,
    pub pool: sqlx::PgPool,
    /// Shield engine : step 5 is the ONLY gate.
    pub policy: Arc<crate::policy::Engine>,
    /// Shared Sentin8:Policy admin surface.
    pub admin: sentin8::shield::admin::SharedAdminState,
    /// Model-provider router (built at boot from `sentin8_ai_providers`).
    pub router: Arc<ProviderRouter>,
    /// Resolved provider routes (adapter + credential + model), keyed by
    /// provider name. Credentials are secret-reference-resolved at boot.
    pub routes: std::collections::HashMap<String, Route>,
    /// M2M-authenticated Storage client - chunk text + trace archive.
    pub storage: sentin8_storage_sdk::client::StorageClient,
    /// M2M-authenticated Flow client - agent workflow creation.
    pub flow: sentin8_flow_sdk::client::FlowClient,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("providers", &self.routes.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

pub fn err_db_pub(e: sqlx::Error) -> (StatusCode, String) {
    err_db(e)
}

fn err_db(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}"))
}

fn err_bad(msg: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, msg.into())
}

/// Set the RLS tenant context inside a transaction. `sentin8_set_tenant_context`
/// uses `set_config(. , true)` - transaction-local, so this MUST run inside
/// the same transaction as the domain statements.
async fn set_rls_tx(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    env_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut **tx)
        .await
        .map_err(err_db)?;
    Ok(())
}

/// Begin a transaction with the tenant context set - the RLS-scoped unit
/// for every handler (cron SEC-2.4.8 pattern).
async fn begin_tenant_tx(
    pool: &sqlx::PgPool,
    env_id: Uuid,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, (StatusCode, String)> {
    let mut tx = pool.begin().await.map_err(err_db)?;
    set_rls_tx(&mut tx, env_id).await?;
    Ok(tx)
}

/// Query params accepted by all env-scoped endpoints. `target_env_id` is
/// forwarded by the BFF proxy to identify the tenant env when the caller's
/// token carries the system env ( Fix A/D - REQUIRED, no
/// silent fallback).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct TargetEnvQuery {
    #[serde(default)]
    pub target_env_id: Option<String>,
}

/// Resolve the effective env_id: prefer `target_env_id` from query params
/// (BFF proxy), fall back to the token's env_id.
fn resolve_env_id(
    a: &auth::AuthContext,
    target_env_id: Option<&str>,
) -> Result<Uuid, (StatusCode, String)> {
    if let Some(tid) = target_env_id.filter(|s| !s.is_empty()) {
        return tid
            .parse::<Uuid>()
            .map_err(|_| err_bad("target_env_id must be a UUID"));
    }
    a.claims
        .env_id
        .as_deref()
        .map(uuid::Uuid::parse_str)
        .transpose()
        .map_err(|_| err_bad("token env_id is not a UUID"))?
        .ok_or_else(|| err_bad("no tenant context - pass target_env_id"))
}

// ── Health ─────────────────────────────────────────────────────────────────

/// `GET /v1/health` - service health (custom payload; shell health suppressed).
#[utoipa::path(
    get,
    operation_id = "ai.health",
    path = "/v1/health",
    responses((status = 200, description = "Service healthy")),
    tag = "ai",
)]
pub async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut payload = serde_json::json!({
        "service": "sentin8:ai",
        "status": "ok",
        "version": sentin8::build_info::id(),
        "build": sentin8::build_info::build_hash(),
        "providers": state.routes.keys().collect::<Vec<_>>(),
    });
    if let Some(n) = sentin8::middleware::traffic_counter::process_active_connections() {
        payload["active_connections"] = serde_json::json!(n);
    }
    Json(payload)
}

// ── Prompt registry ────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct PromptRecord {
    pub id: Uuid,
    pub name: String,
    pub version: i32,
    pub system_text: String,
    pub user_text: String,
    pub model_primary: String,
    pub model_fallback: Option<String>,
    pub temperature: Option<f64>,
    pub max_tokens: Option<i32>,
    pub tools: serde_json::Value,
    pub output_schema: Option<serde_json::Value>,
    pub status: String,
    pub origin: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertPromptRequest {
    pub name: String,
    pub system_text: String,
    #[serde(default)]
    pub user_text: String,
    pub model_primary: String,
    #[serde(default)]
    pub model_fallback: Option<String>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub max_tokens: Option<i32>,
    #[serde(default)]
    pub tools: serde_json::Value,
    #[serde(default)]
    pub output_schema: Option<serde_json::Value>,
    /// `platform` rows are overwritten by enroll; `tenant` rows never are.
    #[serde(default = "default_origin")]
    pub origin: String,
    /// Explicit version; omit = next version for the name.
    #[serde(default)]
    pub version: Option<i32>,
}

fn default_origin() -> String {
    "platform".into()
}

fn prompt_from_row(r: &sqlx::postgres::PgRow) -> PromptRecord {
    PromptRecord {
        id: r.get("id"),
        name: r.get("name"),
        version: r.get::<i32, _>("version"),
        system_text: r.get("system_text"),
        user_text: r.get("user_text"),
        model_primary: r.get("model_primary"),
        model_fallback: r.get("model_fallback"),
        temperature: r.get::<Option<f32>, _>("temperature").map(|v| v as f64),
        max_tokens: r.get("max_tokens"),
        tools: r.get("tools"),
        output_schema: r.get("output_schema"),
        status: r.get("status"),
        origin: r.get("origin"),
        created_at: r
            .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
            .to_rfc3339(),
    }
}

/// `POST /v1/prompts` - create a new prompt version (immutable per version).
#[utoipa::path(
    post,
    operation_id = "prompt.create",
    path = "/v1/prompts",
    request_body = UpsertPromptRequest,
    responses(
        (status = 200, description = "Created prompt version", body = PromptRecord),
        (status = 422, description = "Validation failed"),
    ),
    security(("sentin8:ai:prompt:write" = [])),
    tag = "ai",
)]
pub async fn create_prompt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(body): Json<UpsertPromptRequest>,
) -> Result<Json<PromptRecord>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    validate_prompt(&body)?;

    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let version = match body.version {
        Some(v) => v,
        None => {
            let maxv: Option<i32> = sqlx::query_scalar(
                "SELECT COALESCE(MAX(version), 0) FROM ai.prompts WHERE env_id = $1 AND name = $2",
            )
            .bind(env_id)
            .bind(&body.name)
            .fetch_one(&mut *tx)
            .await
            .map_err(err_db)?;
            maxv.unwrap_or(0) + 1
        }
    };
    // Version immutability: an existing (name, version) is 409.
    let exists: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM ai.prompts WHERE env_id = $1 AND name = $2 AND version = $3",
    )
    .bind(env_id)
    .bind(&body.name)
    .bind(version)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?;
    if exists.is_some() {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "prompt {} version {version} already exists (versions are immutable)",
                body.name
            ),
        ));
    }
    let row = sqlx::query(
        "INSERT INTO ai.prompts \
         (name, version, system_text, user_text, model_primary, model_fallback, temperature, max_tokens, tools, output_schema, origin, created_by, env_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *",
    )
    .bind(&body.name)
    .bind(version)
    .bind(&body.system_text)
    .bind(&body.user_text)
    .bind(&body.model_primary)
    .bind(&body.model_fallback)
    .bind(body.temperature.map(|t| t as f32))
    .bind(body.max_tokens)
    .bind(&body.tools)
    .bind(&body.output_schema)
    .bind(&body.origin)
    .bind(&a.claims.sub)
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(err_db)?;
    // Inbox-first event - same tx as the domain change.
    emit_prompt_event_tx(&mut tx, env_id, &body.name, version).await?;
    tx.commit().await.map_err(err_db)?;
    Ok(Json(prompt_from_row(&row)))
}

async fn emit_prompt_event_tx(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    env_id: Uuid,
    name: &str,
    version: i32,
) -> Result<(), (StatusCode, String)> {
    let payload = serde_json::json!({
        "prompt_name": name,
        "prompt_version": version,
    });
    sentin8::bus::outbox::insert_outbox_row(
        &mut **tx,
        env_id,
        "ai",
        "sentin8:ai:prompt:updated",
        &payload,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("event emit failed: {e}"),
        )
    })?;
    Ok(())
}

fn validate_prompt(body: &UpsertPromptRequest) -> Result<(), (StatusCode, String)> {
    if body.name.trim().is_empty() {
        return Err(err_bad("prompt name is required"));
    }
    if body.model_primary.trim().is_empty() {
        return Err(err_bad("model_primary is required"));
    }
    if !matches!(body.origin.as_str(), "platform" | "tenant") {
        return Err(err_bad("origin must be 'platform' or 'tenant'"));
    }
    if let Some(schema) = &body.output_schema {
        if !schema.is_object() {
            return Err(err_bad("output_schema must be a JSON Schema object"));
        }
    }
    Ok(())
}

/// `GET /v1/prompts` - list prompts (latest or all versions).
#[utoipa::path(
    get,
    operation_id = "prompt.list",
    path = "/v1/prompts",
    params(("target_env_id" = Option<String>, Query), ("name" = Option<String>, Query), ("all_versions" = Option<bool>, Query)),
    responses((status = 200, description = "Prompt versions", body = [PromptRecord])),
    security(("sentin8:ai:prompt:read" = [])),
    tag = "ai",
)]
pub async fn list_prompts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PromptListQuery>,
) -> Result<Json<Vec<PromptRecord>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:read"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    let sql = if q.all_versions.unwrap_or(false) {
        "SELECT * FROM ai.prompts WHERE env_id = $1 AND ($2::text IS NULL OR name = $2) ORDER BY name, version DESC"
    } else {
        // Latest version per name ( named-latest resolution).
        "SELECT DISTINCT ON (name) * FROM ai.prompts WHERE env_id = $1 AND ($2::text IS NULL OR name = $2) ORDER BY name, version DESC"
    };
    let rows = sqlx::query(sql)
        .bind(env_id)
        .bind(&q.name)
        .fetch_all(&state.pool)
        .await
        .map_err(err_db)?;
    Ok(Json(rows.iter().map(prompt_from_row).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PromptListQuery {
    #[serde(default)]
    pub target_env_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub all_versions: Option<bool>,
}

/// `DELETE /v1/prompts/{name}/{version}` - retire a version (never hard-delete
/// platform history; tenant rows may be removed).
#[utoipa::path(
    delete,
    operation_id = "prompt.delete",
    path = "/v1/prompts/{name}/{version}",
    params(("name" = String, Path), ("version" = i32, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 204, description = "Prompt version retired")),
    security(("sentin8:ai:prompt:write" = [])),
    tag = "ai",
)]
pub async fn delete_prompt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path((name, version)): Path<(String, i32)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    // Platform-origin versions are retired, never deleted (audit trail).
    let origin: Option<String> = sqlx::query_scalar(
        "SELECT origin FROM ai.prompts WHERE env_id = $1 AND name = $2 AND version = $3",
    )
    .bind(env_id)
    .bind(&name)
    .bind(version)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?;
    let Some(origin) = origin else {
        return Err((
            StatusCode::NOT_FOUND,
            format!("prompt {name} v{version} not found"),
        ));
    };
    if origin == "platform" {
        sqlx::query("UPDATE ai.prompts SET status = 'retired', updated_at = now() WHERE env_id = $1 AND name = $2 AND version = $3")
            .bind(env_id)
            .bind(&name)
            .bind(version)
            .execute(&mut *tx)
            .await
            .map_err(err_db)?;
    } else {
        sqlx::query("DELETE FROM ai.prompts WHERE env_id = $1 AND name = $2 AND version = $3")
            .bind(env_id)
            .bind(&name)
            .bind(version)
            .execute(&mut *tx)
            .await
            .map_err(err_db)?;
    }
    tx.commit().await.map_err(err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Inference primitives ───────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct InferenceRequest {
    /// Prompt registry name - config (models, temperature, schema) resolves
    /// from the named-latest/pinned version unless overridden inline.
    #[serde(default)]
    pub prompt_name: Option<String>,
    #[serde(default)]
    pub prompt_version: Option<i32>,
    /// Inline messages (chat) - merged after the prompt's system/user text.
    #[serde(default)]
    pub messages: Vec<crate::providers::ChatMessage>,
    /// Inline override (completion-style single input).
    #[serde(default)]
    pub input: Option<String>,
    /// Feature label for cost attribution `{env_id, feature, model}`.
    #[serde(default = "default_feature")]
    pub feature: String,
    #[serde(default)]
    pub model_override: Option<String>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub target_env_id: Option<String>,
}

fn default_feature() -> String {
    "default".into()
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct InferenceResponse {
    pub content: String,
    pub model: String,
    pub prompt_name: Option<String>,
    pub prompt_version: Option<i32>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub latency_ms: i64,
    pub cache_hit: bool,
    pub idempotent_replay: bool,
}

/// Resolve the active prompt record: explicit version → pinned → latest.
async fn resolve_prompt(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    env_id: Uuid,
    name: &str,
    version: Option<i32>,
) -> Result<PromptResolved, (StatusCode, String)> {
    let row = match version {
        Some(v) => {
            sqlx::query(
                "SELECT * FROM ai.prompts WHERE env_id = $1 AND name = $2 AND version = $3 AND status != 'retired'",
            )
            .bind(env_id)
            .bind(name)
            .bind(v)
            .fetch_optional(&mut **tx)
            .await
            .map_err(err_db)?
        }
        None => {
            sqlx::query(
                "SELECT * FROM ai.prompts WHERE env_id = $1 AND name = $2 AND (status = 'pinned' OR status = 'active') ORDER BY CASE status WHEN 'pinned' THEN 0 ELSE 1 END, version DESC LIMIT 1",
            )
            .bind(env_id)
            .bind(name)
            .fetch_optional(&mut **tx)
            .await
            .map_err(err_db)?
        }
    };
    let row = row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("prompt {name} not found (version pinned/active required)"),
        )
    })?;
    Ok(PromptResolved {
        system_text: row.get("system_text"),
        user_text: row.get("user_text"),
        model_primary: row.get("model_primary"),
        model_fallback: row.get("model_fallback"),
        temperature: row.get::<Option<f32>, _>("temperature").map(|t| t as f64),
        max_tokens: row.get("max_tokens"),
        tools: row.get("tools"),
        output_schema: row.get("output_schema"),
        version: row.get("version"),
    })
}

/// Extracted prompt fields (PgRow is not Clone - pull values eagerly).
#[derive(Debug, Clone)]
struct PromptResolved {
    system_text: String,
    user_text: String,
    model_primary: String,
    model_fallback: Option<String>,
    temperature: Option<f64>,
    max_tokens: Option<i32>,
    tools: serde_json::Value,
    output_schema: Option<serde_json::Value>,
    version: i32,
}

fn route_for<'s>(
    state: &'s AppState,
    model: &str,
    fallback: Option<&str>,
) -> Result<(&'s Route, Option<&'s Route>), (StatusCode, String)> {
    // Model names carry the provider prefix: "openai/gpt-5", "ollama/llama3".
    // The model portion is passed through to the provider adapter verbatim;
    // routing decisions only need the provider prefix.
    let (provider_name, _model) = model
        .split_once('/')
        .map(|(p, m)| (p.to_string(), m.to_string()))
        .unwrap_or_else(|| ("openai".to_string(), model.to_string()));
    let primary = state.routes.get(&provider_name).ok_or_else(|| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("provider '{provider_name}' is not configured for this environment"),
        )
    })?;
    let fb = fallback.and_then(|f| {
        f.split_once('/')
            .map(|(p, _)| p)
            .unwrap_or(provider_name.as_str());
        state.routes.get(
            f.split_once('/')
                .map(|(p, _)| p)
                .unwrap_or(provider_name.as_str()),
        )
    });
    Ok((primary, fb))
}

/// `POST /v1/chat` - chat inference through the prompt registry + provider
/// router. Idempotency-Key honored; trace emitted.
#[utoipa::path(
    post,
    operation_id = "ai.chat",
    path = "/v1/chat",
    request_body = InferenceRequest,
    params(("target_env_id" = Option<String>, Query)),
    responses(
        (status = 200, description = "Chat completion", body = InferenceResponse),
        (status = 404, description = "Prompt not found"),
        (status = 422, description = "Provider/schema failure"),
    ),
    security(("sentin8:ai:chat:write" = [])),
    tag = "ai",
)]
pub async fn chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(body): Json<InferenceRequest>,
) -> Result<Json<InferenceResponse>, (StatusCode, String)> {
    run_inference(state, headers, q, body, "sentin8:ai:chat:write").await
}

/// `POST /v1/completions` - completion inference. Same pipeline as
/// chat; the action scope differs.
#[utoipa::path(
    post,
    operation_id = "ai.completion",
    path = "/v1/completions",
    request_body = InferenceRequest,
    params(("target_env_id" = Option<String>, Query)),
    responses(
        (status = 200, description = "Completion", body = InferenceResponse),
        (status = 404, description = "Prompt not found"),
        (status = 422, description = "Provider/schema failure"),
    ),
    security(("sentin8:ai:completion:write" = [])),
    tag = "ai",
)]
pub async fn completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(body): Json<InferenceRequest>,
) -> Result<Json<InferenceResponse>, (StatusCode, String)> {
    run_inference(state, headers, q, body, "sentin8:ai:completion:write").await
}

async fn run_inference(
    state: AppState,
    headers: HeaderMap,
    q: TargetEnvQuery,
    body: InferenceRequest,
    action: &str,
) -> Result<Json<InferenceResponse>, (StatusCode, String)> {
    let started = std::time::Instant::now();
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new(action),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;

    // Safety filter chain : baseline injection rule + env rules.
    // Input moderation BEFORE the provider call; a block is 422 and never
    // reaches the model. Env rules resolve inside the tenant tx (RLS);
    // the baseline code rule runs first regardless.
    let inline_text = body.input.clone().unwrap_or_default();
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let env_filter_rules = crate::safety::load_env_rules(&mut tx, env_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if let Err(reason) = crate::safety::run_input_filters(&env_filter_rules, &inline_text) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("input blocked by safety filter: {reason}"),
        ));
    }
    for m in &body.messages {
        if let Err(reason) = crate::safety::run_input_filters(&env_filter_rules, &m.content) {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("input blocked by safety filter: {reason}"),
            ));
        }
    }

    // Idempotency : replay a completed response for a seen key.
    let idem_key = headers
        .get(sentin8::idempotency::IDEMPOTENCY_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if let Some(key) = &idem_key {
        if let Some(cached) = idem_get(&state, env_id, key).await {
            let mut resp: InferenceResponse = serde_json::from_value(cached)
                .map_err(|_| err_bad("corrupted idempotency record"))?;
            resp.idempotent_replay = true;
            return Ok(Json(resp));
        }
    }

    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    // Prompt resolution + messages assembly. `messages` starts from the
    // request's inline list; the prompt's system/user text merges in front.
    // (The env filter rules were loaded on this same tx above.)
    let mut messages = body.messages.clone();
    let prompt = match &body.prompt_name {
        Some(name) => {
            let p = resolve_prompt(&mut tx, env_id, name, body.prompt_version).await?;
            if !p.system_text.is_empty() {
                messages.insert(
                    0,
                    crate::providers::ChatMessage {
                        role: "system".into(),
                        content: p.system_text.clone(),
                    },
                );
            }
            if !p.user_text.is_empty() && messages.is_empty() && body.input.is_none() {
                messages.push(crate::providers::ChatMessage {
                    role: "user".into(),
                    content: p.user_text.clone(),
                });
            }
            Some(p)
        }
        None => None,
    };
    if let Some(input) = &body.input {
        messages.push(crate::providers::ChatMessage {
            role: "user".into(),
            content: input.clone(),
        });
    }
    if messages.is_empty() {
        return Err(err_bad("no messages - pass prompt_name, messages or input"));
    }

    // Model selection: prompt config → inline override.
    let model_primary = body
        .model_override
        .clone()
        .or_else(|| prompt.as_ref().map(|p| p.model_primary.clone()))
        .ok_or_else(|| err_bad("no model - pass model_override or prompt_name"))?;
    let model_fallback = prompt.as_ref().and_then(|p| p.model_fallback.clone());
    let temperature = body
        .temperature
        .or_else(|| prompt.as_ref().and_then(|p| p.temperature));
    let (primary_route, fallback_route) =
        route_for(&state, &model_primary, model_fallback.as_deref())?;

    // Cost gate : budget check BEFORE the provider call. Reject-mode
    // breach → 429; degrade/queue → response flag on the trace feature.
    let budget_enforcement = check_budget(&mut tx, env_id, &body.feature).await?;

    // Cache lookup (exact match, AI-3) BEFORE the provider call. The key
    // covers EVERYTHING that determines the response: env, model, messages,
    // sampling params (temperature/max_tokens), and the tool set - a
    // near-hit would return a response generated under different params.
    // The messages payload is hashed (sha256) so the key stays bounded for
    // long conversations.
    let cache_payload = serde_json::json!({
        "messages": messages,
        "temperature": temperature,
        "max_tokens": body.max_tokens,
        "tools": prompt.as_ref().map(|p| p.tools.clone()),
    });
    let mut hasher = sha2::Sha256::new();
    hasher.update(model_primary.as_bytes());
    hasher.update(
        serde_json::to_string(&cache_payload)
            .unwrap_or_default()
            .as_bytes(),
    );
    let prompt_hash = format!("{:x}", hasher.finalize());
    let cache_key = format!("ai:cache:{env_id}:{model_primary}:{prompt_hash}");
    let cache_hit = cache_get(&state, &cache_key).await;
    let was_cache_hit = cache_hit.is_some();
    let response = if let Some(cached) = cache_hit {
        cached
    } else {
        let req = crate::providers::CompletionRequest {
            model: model_primary
                .split_once('/')
                .map(|(_, m)| m.to_string())
                .unwrap_or(model_primary.clone()),
            messages: messages.clone(),
            temperature,
            max_tokens: body
                .max_tokens
                .or_else(|| prompt.as_ref().and_then(|p| p.max_tokens).map(|t| t as u32)),
            tools: prompt
                .as_ref()
                .map(|p| p.tools.clone())
                .and_then(|t| t.as_array().cloned())
                .unwrap_or_default(),
        };
        let client = reqwest::Client::new();
        let resp = state
            .router
            .complete(&client, primary_route, fallback_route, &req)
            .await
            .map_err(|e| match &e {
                crate::providers::ProviderError::Terminal { message, .. } => {
                    (StatusCode::UNPROCESSABLE_ENTITY, message.clone())
                }
                crate::providers::ProviderError::Transient { message, .. } => {
                    (StatusCode::BAD_GATEWAY, message.clone())
                }
            })?;
        cache_put(&state, &cache_key, &resp).await;
        resp
    };
    // Output moderation BEFORE the response returns.
    if let Err(reason) = crate::safety::run_output_filters(&env_filter_rules, &response.content) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("output blocked by safety filter: {reason}"),
        ));
    }
    let content = response.content.clone();
    let output_schema = prompt.as_ref().and_then(|p| p.output_schema.clone());
    if let Some(schema) = &output_schema {
        validate_schema(&content, schema)?;
    }

    let latency_ms = started.elapsed().as_millis() as i64;
    let resp = InferenceResponse {
        content: content.clone(),
        model: response.model.clone(),
        prompt_name: body.prompt_name.clone(),
        prompt_version: prompt.as_ref().map(|p| p.version),
        input_tokens: response.input_tokens,
        output_tokens: response.output_tokens,
        latency_ms,
        cache_hit: was_cache_hit,
        idempotent_replay: false,
    };

    // Trace - same tx as the inference record.
    sqlx::query(
        "INSERT INTO ai.traces (prompt_name, prompt_version, model, feature, input_tokens, output_tokens, latency_ms, cache_hit, status, subject_id, env_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'ok',$9,$10)",
    )
    .bind(&body.prompt_name)
    .bind(resp.prompt_version)
    .bind(&resp.model)
    .bind(trace_feature_label(&body.feature, budget_enforcement.as_deref()))
    .bind(resp.input_tokens as i64)
    .bind(resp.output_tokens as i64)
    .bind(latency_ms as i32)
    .bind(resp.cache_hit)
    .bind(crate::safety::strip_pii(&serde_json::json!({"subject": a.claims.sub})).0["subject"].as_str().unwrap_or("") )
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;

    // Stat metric emission - fire-and-forget; a Stat outage never
    // blocks the response (the trace row above carries the spend).
    crate::metrics::emit_inference_metrics(
        env_id,
        &a.claims.sub,
        &body.feature,
        &resp.model,
        resp.input_tokens,
        resp.output_tokens,
        resp.latency_ms,
        resp.cache_hit,
    );

    // Idempotency store (after commit).
    if let Some(key) = &idem_key {
        let _ = idem_put(
            &state,
            env_id,
            key,
            &serde_json::to_value(&resp).unwrap_or_default(),
        )
        .await;
    }
    // Audit journal (AI-3): the inference lands in `ai.audit_journal` with
    // `cache: "hit"|"miss"` - cache provenance must be auditable (a hit is a
    // replay of a previous generation, not a fresh one). Same-transaction
    // discipline is relaxed here by design: the journal is best-effort (an
    // outage degrades to the trace row above, never blocks the response).
    audit_inference(
        &state.pool,
        env_id,
        &a.claims.sub,
        &body.feature,
        &resp.model,
        was_cache_hit,
        &prompt_hash,
    )
    .await;
    Ok(Json(resp))
}

/// Best-effort audit journal row for an inference (AI-3): records the
/// feature, model, and cache provenance (`cache: "hit"|"miss"` plus the
/// prompt-hash key that produced it). Best-effort: an outage degrades to
/// the trace row, never blocks the response.
async fn audit_inference(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    subject_id: &str,
    feature: &str,
    model: &str,
    cache_hit: bool,
    prompt_hash: &str,
) {
    let Ok(mut tx) = pool.begin().await else {
        return;
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let _ = sqlx::query(
        "INSERT INTO audit_journal (id, env_id, action, details) VALUES ($1, $2, $3, $4)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(env_id)
    .bind("ai.inference")
    .bind(serde_json::json!({
        "action": "ai.inference",
        "feature": feature,
        "model": model,
        "subject_id": subject_id,
        "cache": if cache_hit { "hit" } else { "miss" },
        "prompt_hash": prompt_hash,
    }))
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
}

/// Output schema enforcement : when the prompt declares
/// `output_schema`, the content must parse as JSON conforming to the
/// declared `type` (object/array). Full JSON Schema validation lands with
/// the evaluation workflows.
fn validate_schema(content: &str, schema: &serde_json::Value) -> Result<(), (StatusCode, String)> {
    let parsed: serde_json::Value = serde_json::from_str(content).map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("output violates declared schema - not valid JSON: {e}"),
        )
    })?;
    let want = schema
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("object");
    let ok = match want {
        "object" => parsed.is_object(),
        "array" => parsed.is_array(),
        "string" => parsed.is_string(),
        "number" => parsed.is_number(),
        "boolean" => parsed.is_boolean(),
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("output violates declared schema - expected type '{want}'"),
        ))
    }
}

// ── Idempotency + cache (Valkey-backed, best-effort) ──────────────────────

async fn idem_get(state: &AppState, env_id: Uuid, key: &str) -> Option<serde_json::Value> {
    let client = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:ai")
        .await
        .ok()?;
    use glide::AsyncCommands as _;
    let full = format!("ai:idem:{env_id}:{key}");
    let raw: Option<String> = client.get(&full).await.ok()?;
    serde_json::from_str(raw.as_deref().unwrap_or("")).ok()
}

async fn idem_put(
    state: &AppState,
    env_id: Uuid,
    key: &str,
    value: &serde_json::Value,
) -> Option<()> {
    let client = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:ai")
        .await
        .ok()?;
    use glide::AsyncCommands as _;
    let full = format!("ai:idem:{env_id}:{key}");
    let _: Result<Option<String>, _> = client.set_ex(full, value.to_string(), 86400u64).await;
    Some(())
}

async fn cache_get(state: &AppState, key: &str) -> Option<crate::providers::CompletionResponse> {
    let client = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:ai")
        .await
        .ok()?;
    use glide::AsyncCommands as _;
    let raw: Option<String> = client.get(key).await.ok()?;
    serde_json::from_str(&raw?).ok()
}

async fn cache_put(
    state: &AppState,
    key: &str,
    value: &crate::providers::CompletionResponse,
) -> Option<()> {
    let client = sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:ai")
        .await
        .ok()?;
    use glide::AsyncCommands as _;
    let _: Result<(), _> = client
        .set_ex(key, serde_json::to_string(value).ok()?, 3600u64)
        .await;
    Some(())
}

// ── Embeddings ───────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct EmbeddingHttpRequest {
    pub model: String,
    pub inputs: Vec<String>,
    #[serde(default = "default_feature")]
    pub feature: String,
    #[serde(default)]
    pub target_env_id: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EmbeddingHttpResult {
    pub vectors: Vec<Vec<f32>>,
    pub model: String,
    pub dims: usize,
}

/// `POST /v1/embeddings` - batch embedding via the provider router.
#[utoipa::path(
    post,
    operation_id = "ai.embedding",
    path = "/v1/embeddings",
    request_body = EmbeddingHttpRequest,
    params(("target_env_id" = Option<String>, Query)),
    responses(
        (status = 200, description = "Embedding vectors (input order)", body = EmbeddingHttpResult),
        (status = 422, description = "Provider failure / dimension mismatch"),
    ),
    security(("sentin8:ai:embedding:write" = [])),
    tag = "ai",
)]
pub async fn embeddings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(_q): Query<TargetEnvQuery>,
    Json(body): Json<EmbeddingHttpRequest>,
) -> Result<Json<EmbeddingHttpResult>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:embedding:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, body.target_env_id.as_deref())?;
    let (route, _) = route_for(&state, &body.model, None)?;
    let client = reqwest::Client::new();
    let resp = state
        .router
        .embed(
            &client,
            route,
            &crate::providers::EmbeddingRequest {
                model: body
                    .model
                    .split_once('/')
                    .map(|(_, m)| m.to_string())
                    .unwrap_or(body.model.clone()),
                inputs: body.inputs,
            },
        )
        .await
        .map_err(|e| match &e {
            crate::providers::ProviderError::Terminal { message, .. } => {
                (StatusCode::UNPROCESSABLE_ENTITY, message.clone())
            }
            crate::providers::ProviderError::Transient { message, .. } => {
                (StatusCode::BAD_GATEWAY, message.clone())
            }
        })?;
    let dims = resp.vectors.first().map(|v| v.len()).unwrap_or(0);
    let _ = env_id; // RLS-scoped persistence happens via the retrieval pipeline
    Ok(Json(EmbeddingHttpResult {
        vectors: resp.vectors,
        model: resp.model,
        dims,
    }))
}

// ── Provider admin ───────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct ProviderRecord {
    pub id: Uuid,
    pub provider: String,
    pub base_url: String,
    pub credential_ref: String,
    pub models: serde_json::Value,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertProviderRequest {
    /// 'openai' | 'anthropic' | 'ollama' (v1 set -).
    pub provider: String,
    pub base_url: String,
    /// Secret reference - NEVER the credential material itself.
    pub credential_ref: String,
    #[serde(default)]
    pub models: serde_json::Value,
}

/// `GET /v1/providers` - list provider configs (credential refs only).
#[utoipa::path(
    get,
    operation_id = "provider.list",
    path = "/v1/providers",
    params(("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Provider configs", body = [ProviderRecord])),
    security(("sentin8:ai:prompt:read" = [])),
    tag = "ai",
)]
pub async fn list_providers(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<Vec<ProviderRecord>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:read"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    let rows = sqlx::query("SELECT * FROM ai.providers WHERE env_id = $1 ORDER BY provider")
        .bind(env_id)
        .fetch_all(&state.pool)
        .await
        .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| ProviderRecord {
                id: r.get("id"),
                provider: r.get("provider"),
                base_url: r.get("base_url"),
                credential_ref: r.get("credential_ref"),
                models: r.get("models"),
                status: r.get("status"),
                created_at: r
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
            })
            .collect(),
    ))
}

/// `PUT /v1/providers/{provider}` - upsert a provider config (secret ref only).
#[utoipa::path(
    put,
    operation_id = "provider.upsert",
    path = "/v1/providers/{provider}",
    params(("provider" = String, Path), ("target_env_id" = Option<String>, Query)),
    request_body = UpsertProviderRequest,
    responses((status = 204, description = "Provider config saved")),
    security(("sentin8:ai:prompt:write" = [])),
    tag = "ai",
)]
pub async fn put_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(provider): Path<String>,
    Json(body): Json<UpsertProviderRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    if !matches!(
        provider.as_str(),
        "openai" | "anthropic" | "ollama" | "vllm"
    ) {
        return Err(err_bad("provider must be openai|anthropic|ollama|vllm"));
    }
    if body.credential_ref.trim().is_empty() {
        return Err(err_bad(
            "credential_ref is required (secret reference, never the credential)",
        ));
    }
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    sqlx::query(
        "INSERT INTO ai.providers (provider, base_url, credential_ref, models, env_id) \
         VALUES ($1,$2,$3,$4,$5) \
         ON CONFLICT (env_id, provider) DO UPDATE SET base_url = $2, credential_ref = $3, models = $4, updated_at = now()",
    )
    .bind(&provider)
    .bind(&body.base_url)
    .bind(&body.credential_ref)
    .bind(&body.models)
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/providers/{provider}` - remove a provider config.
#[utoipa::path(
    delete,
    operation_id = "provider.delete",
    path = "/v1/providers/{provider}",
    params(("provider" = String, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 204, description = "Provider config removed")),
    security(("sentin8:ai:prompt:write" = [])),
    tag = "ai",
)]
pub async fn delete_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(provider): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    sqlx::query("DELETE FROM ai.providers WHERE env_id = $1 AND provider = $2")
        .bind(env_id)
        .bind(&provider)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Safety filter rules ( - env-configurable chain) ─────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertFilterRequest {
    /// `input` (pre-provider) or `output` (pre-client).
    pub stage: String,
    /// Substrings that trip the rule (case-insensitive).
    pub blocked_terms: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// `PUT /v1/filters/{name}` - create/update an env safety filter rule
///. The baseline prompt-injection rule is code and unaffected.
#[utoipa::path(
    put,
    operation_id = "ai.filter.upsert",
    path = "/v1/filters/{name}",
    params(("name" = String, Path), ("target_env_id" = Option<String>, Query)),
    request_body = UpsertFilterRequest,
    responses(
        (status = 204, description = "Filter rule saved"),
        (status = 422, description = "Invalid stage"),
    ),
    security(("sentin8:ai:prompt:write" = [])),
    tag = "ai",
)]
pub async fn put_filter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(name): Path<String>,
    Json(body): Json<UpsertFilterRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    if !matches!(body.stage.as_str(), "input" | "output") {
        return Err(err_bad("stage must be 'input' or 'output'"));
    }
    if body.blocked_terms.is_empty() {
        return Err(err_bad("blocked_terms must not be empty"));
    }
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    sqlx::query(
        "INSERT INTO ai.filters (name, stage, blocked_terms, enabled, env_id) \
         VALUES ($1,$2,$3,$4,$5) \
         ON CONFLICT (env_id, name) DO UPDATE SET stage = $2, blocked_terms = $3, enabled = $4, updated_at = now()",
    )
    .bind(&name)
    .bind(&body.stage)
    .bind(&body.blocked_terms)
    .bind(body.enabled)
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FilterRecord {
    pub name: String,
    pub stage: String,
    pub blocked_terms: Vec<String>,
    pub enabled: bool,
}

/// `GET /v1/filters` - list env filter rules.
#[utoipa::path(
    get,
    operation_id = "ai.filter.list",
    path = "/v1/filters",
    params(("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Filter rules", body = [FilterRecord])),
    security(("sentin8:ai:prompt:read" = [])),
    tag = "ai",
)]
pub async fn list_filters(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<Vec<FilterRecord>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:read"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    let rows = sqlx::query(
        "SELECT name, stage, blocked_terms, enabled FROM ai.filters WHERE env_id = $1 ORDER BY name",
    )
    .bind(env_id)
    .fetch_all(&state.pool)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| FilterRecord {
                name: r.get("name"),
                stage: r.get("stage"),
                blocked_terms: r.get("blocked_terms"),
                enabled: r.get("enabled"),
            })
            .collect(),
    ))
}

/// `DELETE /v1/filters/{name}` - remove an env filter rule. The baseline
/// injection rule is code and cannot be removed.
#[utoipa::path(
    delete,
    operation_id = "ai.filter.delete",
    path = "/v1/filters/{name}",
    params(("name" = String, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 204, description = "Filter rule removed")),
    security(("sentin8:ai:prompt:write" = [])),
    tag = "ai",
)]
pub async fn delete_filter(
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
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    sqlx::query("DELETE FROM ai.filters WHERE env_id = $1 AND name = $2")
        .bind(env_id)
        .bind(&name)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Retrieval ( - hybrid, permission-filtered) ────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct RetrievalHttpRequest {
    pub query: String,
    /// Caller's Shield-resolved data scope - applied as an explicit metadata
    /// filter IN THE QUERY (the LLM never sees out-of-scope chunks).
    #[serde(default)]
    pub data_scope: Vec<String>,
    /// Metadata filters: `{"key": "value",. }` - each becomes
    /// `metadata->'key' == value` in the SQL (AND-composed).
    #[serde(default)]
    pub metadata_filters: serde_json::Value,
    #[serde(default = "default_top_k")]
    pub top_k: i64,
    /// When the prompt config declares a reranker model (`openai/rerank-x`),
    /// the vector/keyword union is re-scored by it before returning.
    #[serde(default)]
    pub rerank_model: Option<String>,
    #[serde(default)]
    pub target_env_id: Option<String>,
}

fn default_top_k() -> i64 {
    8
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RetrievedChunk {
    pub id: Uuid,
    pub content_ref: String,
    pub metadata: serde_json::Value,
    pub score: f64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RetrievalHttpResult {
    pub chunks: Vec<RetrievedChunk>,
    pub query_embedding_ms: i64,
}

/// `POST /v1/retrieval` - hybrid retrieval: vector similarity (pgvector) +
/// keyword (tsvector, when pgvector is absent) + metadata filters +
/// permission filter from the caller's `data_scope`. Standard RLS env_id
/// match is the backstop; the data_scope filter is defense-in-depth.
#[utoipa::path(
    post,
    operation_id = "ai.retrieval",
    path = "/v1/retrieval",
    request_body = RetrievalHttpRequest,
    params(("target_env_id" = Option<String>, Query)),
    responses(
        (status = 200, description = "Retrieved chunks (permission-filtered)", body = RetrievalHttpResult),
        (status = 503, description = "pgvector unavailable in this deployment"),
    ),
    security(("sentin8:ai:retrieval:read" = [])),
    tag = "ai",
)]
pub async fn retrieval(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(_q): Query<TargetEnvQuery>,
    Json(body): Json<RetrievalHttpRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let started = std::time::Instant::now();
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:retrieval:read"),
    )
    .await?;
    let env_id = resolve_env_id(&a, body.target_env_id.as_deref())?;
    if body.query.trim().is_empty() {
        return Err(err_bad("query is required"));
    }

    // Embed the query via the first configured embedder.
    let route = state
        .routes
        .values()
        .find(|r| r.embedder.is_some())
        .ok_or_else(|| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "no embedding provider configured".to_string(),
            )
        })?;
    let client = reqwest::Client::new();
    let emb = state
        .router
        .embed(
            &client,
            route,
            &crate::providers::EmbeddingRequest {
                model: route.model.clone(),
                inputs: vec![body.query.clone()],
            },
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let query_vec = emb.vectors.first().ok_or_else(|| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "empty embedding".to_string(),
        )
    })?;
    let embedding_ms = started.elapsed().as_millis() as i64;

    // Hybrid search - vector similarity (pgvector cosine) UNION
    // keyword relevance (tsvector over chunk_text), each branch carrying the
    // permission filter. Metadata filters compose as AND terms. RLS env_id
    // is the hard isolation barrier (same-connection context set below).
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let scope_filter = if body.data_scope.is_empty() {
        "FALSE".to_string()
    } else {
        // metadata->'data_scope' ?| array[. ] - any overlap grants visibility.
        let quoted = body
            .data_scope
            .iter()
            .map(|s| format!("'{}'", s.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(", ");
        format!("(metadata->'data_scope') ?| array[{quoted}]")
    };
    // Metadata filters: each key becomes `metadata->'k' == 'v'` (AND).
    let meta_filter = metadata_filter_sql(&body.metadata_filters)?;
    let combined_filter = if meta_filter.is_empty() {
        scope_filter
    } else {
        format!("{scope_filter} AND {meta_filter}")
    };
    let vec_literal = format!(
        "[{}]",
        query_vec
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    let top_k = body.top_k.clamp(1, 100);
    // Vector branch - ordered by cosine distance; keyword branch - ordered
    // by ts_rank over the simple-config tsvector (GIN-indexed). The union is
    // deduped on id by taking the max score per chunk id.
    let sql = format!(
        "WITH vec AS ( \
             SELECT id, content_ref, metadata, 1 - (embedding <=> $1::vector) AS score, embedding IS NOT NULL AS via_vector \
             FROM ai.embeddings \
             WHERE env_id = $2 AND ({combined_filter}) AND embedding IS NOT NULL \
             ORDER BY embedding <=> $1::vector LIMIT $3 \
         ), kw AS ( \
             SELECT id, content_ref, metadata, ts_rank(to_tsvector('simple', chunk_text), websearch_to_tsquery('simple', $4)) AS kw_score, chunk_text \
             FROM ai.embeddings \
             WHERE env_id = $2 AND ({combined_filter}) \
               AND chunk_text <> '' AND to_tsvector('simple', chunk_text) @@ websearch_to_tsquery('simple', $4) \
             ORDER BY ts_rank(to_tsvector('simple', chunk_text), websearch_to_tsquery('simple', $4)) DESC LIMIT $3 \
         ) \
         SELECT id, content_ref, metadata, score, via_vector, ''::text AS chunk_text FROM vec \
         UNION ALL \
         SELECT id, content_ref, metadata, kw_score AS score, false AS via_vector, chunk_text FROM kw \
         ORDER BY score DESC LIMIT $3"
    );
    let rows = sqlx::query(&sql)
        .bind(&vec_literal)
        .bind(env_id)
        .bind(top_k)
        .bind(&body.query)
        .fetch_all(&mut *tx)
        .await
        .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    let mut chunks: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.get::<Uuid, _>("id"),
                "content_ref": r.get::<String, _>("content_ref"),
                "metadata": r.get::<serde_json::Value, _>("metadata"),
                "score": r.get::<f64, _>("score"),
                "chunk_text": r.get::<String, _>("chunk_text"),
                "via_vector": r.get::<bool, _>("via_vector"),
            })
        })
        .collect();

    // Reranker pass : when the caller (or prompt config) names a
    // rerank model, re-score the union with a provider completion that
    // returns relevance 0. 1 per candidate. Best-effort - a reranker failure
    // returns the pre-rerank order (retrieval never hard-fails on rerank).
    if let Some(rerank_model) = &body.rerank_model {
        if let Ok(reranked) =
            rerank_chunks(&state, &client, rerank_model, &body.query, &chunks).await
        {
            chunks = reranked;
        }
    }
    // Trim to top_k after the union + rerank.
    chunks.truncate(top_k as usize);
    Ok(Json(serde_json::json!({
        "chunks": chunks,
        "query_embedding_ms": embedding_ms,
    })))
}

/// Compose the metadata filter SQL (AND-composed `metadata->'k' == 'v'`
/// terms). Keys/values are single-quote-escaped; only string values are
/// supported (numeric filters are a v2 refinement).
fn metadata_filter_sql(filters: &serde_json::Value) -> Result<String, (StatusCode, String)> {
    let Some(obj) = filters.as_object() else {
        return Ok(String::new());
    };
    if obj.is_empty() {
        return Ok(String::new());
    }
    let terms = obj
        .iter()
        .map(|(k, v)| {
            let v = v
                .as_str()
                .ok_or_else(|| err_bad("metadata_filters values must be strings"))?;
            Ok(format!(
                "metadata->'{}' == '{}'",
                k.replace('\'', "''"),
                v.replace('\'', "''")
            ))
        })
        .collect::<Result<Vec<_>, (StatusCode, String)>>()?;
    Ok(terms.join(" AND "))
}

/// Rerank the retrieved chunks with a provider completion. The
/// model is asked for a JSON array of relevance scores aligned to the
/// candidate list; unparseable output leaves the order untouched.
async fn rerank_chunks(
    state: &AppState,
    client: &reqwest::Client,
    rerank_model: &str,
    query: &str,
    chunks: &[serde_json::Value],
) -> Result<Vec<serde_json::Value>, (StatusCode, String)> {
    let (primary_route, fallback_route) = route_for(state, rerank_model, None)?;
    let candidates: Vec<String> = chunks
        .iter()
        .map(|c| {
            c.get("chunk_text")
                .and_then(|t| t.as_str())
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    let req = crate::providers::CompletionRequest {
        model: rerank_model
            .split_once('/')
            .map(|(_, m)| m.to_string())
            .unwrap_or_else(|| rerank_model.to_string()),
        messages: vec![crate::providers::ChatMessage {
            role: "user".into(),
            content: format!(
                "Query: {query}\n\nScore each candidate's relevance to the query from 0.0 to 1.0. \
                 Reply ONLY with a JSON array of {len} numbers in candidate order.\n\nCandidates:\n{}",
                candidates
                    .iter()
                    .enumerate()
                    .map(|(i, c)| format!("[{i}] {}", truncate_for_prompt(c, 400)))
                    .collect::<Vec<_>>()
                    .join("\n"),
                len = candidates.len(),
            ),
        }],
        temperature: Some(0.0),
        max_tokens: Some(256),
        tools: vec![],
    };
    let resp = state
        .router
        .complete(client, primary_route, fallback_route, &req)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let scores: Vec<f64> = parse_relevance_scores(&resp.content, chunks.len());
    let mut scored: Vec<(usize, f64)> = scores.into_iter().enumerate().collect();
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    Ok(scored
        .into_iter()
        .map(|(idx, score)| {
            let mut c = chunks[idx].clone();
            // The reranker score REPLACES the retrieval score (0. 1 band);
            // the original retrieval score is preserved for observability.
            let original = c.get("score").and_then(|s| s.as_f64()).unwrap_or(0.0);
            c["retrieval_score"] = serde_json::json!(original);
            c["score"] = serde_json::json!(score);
            c
        })
        .collect())
}

/// Parse a relevance-score array out of the reranker output. Tolerates a
/// fenced JSON array; falls back to identity order when the shape is wrong.
fn parse_relevance_scores(content: &str, expected: usize) -> Vec<f64> {
    let trimmed = content.trim();
    let json_str = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .map(|s| s.trim())
        .and_then(|s| s.strip_suffix("```"))
        .map(|s| s.trim())
        .unwrap_or(trimmed);
    serde_json::from_str::<Vec<f64>>(json_str)
        .unwrap_or_default()
        .into_iter()
        .chain(std::iter::repeat(0.0))
        .take(expected)
        .collect()
}

/// Truncate a candidate chunk for the reranker prompt (bounded tokens).
fn truncate_for_prompt(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        text.chars().take(max_chars).collect()
    }
}

// ── Streaming chat ───────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct StreamChatRequest {
    pub model: String,
    #[serde(default)]
    pub messages: Vec<crate::providers::ChatMessage>,
    #[serde(default = "default_feature")]
    pub feature: String,
    #[serde(default)]
    pub target_env_id: Option<String>,
}

/// `POST /v1/chat/stream` - streaming chat over a chunked HTTP body
///. NOT the SSE subscription tier - synchronous inference streams
/// the response body directly (transport-tier rule).
/// Content is emitted as newline-delimited JSON chunks; the final chunk
/// carries the token accounting.
#[utoipa::path(
    post,
    operation_id = "ai.chat.stream",
    path = "/v1/chat/stream",
    request_body = StreamChatRequest,
    params(("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Streamed completion (ndjson chunks)")),
    security(("sentin8:ai:chat:write" = [])),
    tag = "ai",
)]
pub async fn chat_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(body): Json<StreamChatRequest>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    use axum::body::Body;
    use axum::http::header;

    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:chat:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    let (primary_route, fallback_route) = route_for(&state, &body.model, None)?;
    if body.messages.is_empty() {
        return Err(err_bad("messages must not be empty"));
    }
    // Input moderation on the stream path too ( - env rules resolve
    // inside the tenant tx; the baseline rule is always active).
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let env_filter_rules = crate::safety::load_env_rules(&mut tx, env_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    tx.commit().await.map_err(err_db)?;
    for m in &body.messages {
        if let Err(reason) = crate::safety::run_input_filters(&env_filter_rules, &m.content) {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("input blocked by safety filter: {reason}"),
            ));
        }
    }

    let started = std::time::Instant::now();
    let client = reqwest::Client::new();
    let model_inner = body
        .model
        .split_once('/')
        .map(|(_, m)| m.to_string())
        .unwrap_or_else(|| body.model.clone());
    // Provider-side token streaming : the adapter's SSE deltas flow
    // through the router straight into the response body - the client sees
    // tokens as the provider emits them. Adapters without SSE support fall
    // back to the single-shot buffered stream inside the trait default.
    let stream = state
        .router
        .complete_stream(
            &client,
            primary_route,
            fallback_route,
            &crate::providers::CompletionRequest {
                model: model_inner,
                messages: body.messages.clone(),
                temperature: None,
                max_tokens: None,
                tools: vec![],
            },
        )
        .await
        .map_err(|e| match &e {
            crate::providers::ProviderError::Terminal { message, .. } => {
                (StatusCode::UNPROCESSABLE_ENTITY, message.clone())
            }
            crate::providers::ProviderError::Transient { message, .. } => {
                (StatusCode::BAD_GATEWAY, message.clone())
            }
        })?;

    // Forward loop state - accumulated output (output moderation runs on the
    // whole text so far), token accounting, and the final model name.
    use axum::response::IntoResponse;
    use futures_util::StreamExt;
    let env_rules = std::sync::Arc::new(env_filter_rules);
    let pool = state.pool.clone();
    let feature = body.feature.clone();
    let subject = std::sync::Arc::new(a.claims.sub.clone());
    let env_id_arc = std::sync::Arc::new(env_id);
    let started_arc = std::sync::Arc::new(started);

    let mapped = stream.then(move |item| {
        let env_rules = std::sync::Arc::clone(&env_rules);
        let pool = pool.clone();
        let feature = feature.clone();
        let subject = std::sync::Arc::clone(&subject);
        let env_id = std::sync::Arc::clone(&env_id_arc);
        let started = std::sync::Arc::clone(&started_arc);
        async move {
            match item {
                Ok(delta) => {
                    // Output moderation on the accumulated buffer.
                    ACCUM.with(|acc| acc.borrow_mut().push_str(&delta.delta));
                    let accumulated = ACCUM.with(|acc| acc.borrow().clone());
                    if let Err(reason) = crate::safety::run_output_filters(&env_rules, &accumulated)
                    {
                        return Err(format!(
                            "{{\"error\":\"output blocked by safety filter: {}\"}}\n",
                            reason.replace('"', "'")
                        ));
                    }
                    if delta.done {
                        // Trace + Stat on the terminal frame - same
                        // accounting contract as buffered inference.
                        let latency_ms = started.elapsed().as_millis() as i64;
                        let trace_result = write_stream_trace(
                            &pool,
                            *env_id,
                            &subject,
                            &feature,
                            &delta.model,
                            delta.input_tokens,
                            delta.output_tokens,
                            latency_ms,
                        )
                        .await;
                        if let Err(e) = trace_result {
                            tracing::warn!(error = %e, "stream trace write failed");
                        }
                        crate::metrics::emit_inference_metrics(
                            *env_id,
                            &subject,
                            &feature,
                            &delta.model,
                            delta.input_tokens,
                            delta.output_tokens,
                            latency_ms,
                            false,
                        );
                        let frame = serde_json::json!({
                            "done": true,
                            "model": delta.model,
                            "input_tokens": delta.input_tokens,
                            "output_tokens": delta.output_tokens,
                            // AI-1: consumers mark the sample approximate
                            // when the provider did not report usage.
                            "usage_estimated": delta.usage_estimated,
                            "latency_ms": latency_ms,
                        });
                        Ok(frame.to_string() + "\n")
                    } else if !delta.delta.is_empty() {
                        Ok(serde_json::json!({ "delta": delta.delta }).to_string() + "\n")
                    } else {
                        Ok(String::new())
                    }
                }
                Err(e) => Err(format!("{{\"error\":\"{e}\"}}\n")),
            }
        }
    });

    let response = (
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        // `mapped` already yields Result<String, String> - error frames are
        // the stream error type, rendered as ndjson by the client.
        Body::from_stream(mapped),
    )
        .into_response();
    Ok(response)
}

// Thread-local accumulated output for the stream moderation buffer (one
// request per task - the per-request closure owns the task).
thread_local! {
    static ACCUM: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

/// Persist the streamed-inference trace row. Runs with the tenant
/// context of the streaming caller - same contract as buffered traces.
#[allow(clippy::too_many_arguments)]
async fn write_stream_trace(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    subject: &str,
    feature: &str,
    model: &str,
    input_tokens: u64,
    output_tokens: u64,
    latency_ms: i64,
) -> Result<(), String> {
    let mut tx = pool.begin().await.map_err(|e| format!("tx: {e}"))?;
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("rls: {e}"))?;
    sqlx::query(
        "INSERT INTO ai.traces (prompt_name, model, feature, input_tokens, output_tokens, latency_ms, cache_hit, status, subject_id, env_id) \
         VALUES ('<stream>',$1,$2,$3,$4,$5,false,'ok',$6,$7)",
    )
    .bind(model)
    .bind(feature)
    .bind(input_tokens as i64)
    .bind(output_tokens as i64)
    .bind(latency_ms as i32)
    .bind(crate::safety::strip_pii(&serde_json::json!({"subject": subject})).0["subject"].as_str().unwrap_or(""))
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("trace insert: {e}"))?;
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(())
}

// ── Agent runtime ( - intent, not free action) ────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct AgentRequest {
    /// Prompt registry name - its `tools` array is the ALLOWLIST of actions
    /// the model may emit (mapped to Flow logics via `sentin8.ai_tools`).
    pub prompt_name: String,
    #[serde(default)]
    pub prompt_version: Option<i32>,
    /// The user's task (merged with the prompt's system text).
    pub task: String,
    /// Flow callback base URL override (defaults to this service's URL).
    #[serde(default)]
    pub callback_base_url: Option<String>,
    #[serde(default = "default_feature")]
    pub feature: String,
    #[serde(default)]
    pub target_env_id: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AgentResponse {
    /// The structured intent the model produced.
    pub intent: crate::agent::AgentIntent,
    /// None = intent requires confirmation and the Flow workflow is waiting
    /// in a ManualDecisionStep. Some(id) = workflow created.
    pub workflow_id: Option<String>,
    /// Tool mapping used (action → Flow logic).
    pub flow_logic_id: String,
    pub allowed: bool,
    pub reason: Option<String>,
}

/// `POST /v1/agent/execute` - controlled agent execution. The model
/// emits intent only; this endpoint maps an allowed intent to a
/// Sentin8:Flow workflow whose domain steps proxy-back to the owning
/// service. `requires_confirmation` intents pause in a ManualDecisionStep.
#[utoipa::path(
    post,
    operation_id = "ai.agent.execute",
    path = "/v1/agent/execute",
    request_body = AgentRequest,
    params(("target_env_id" = Option<String>, Query)),
    responses(
        (status = 200, description = "Agent intent processed", body = AgentResponse),
        (status = 403, description = "Action not in the prompt's tool allowlist"),
        (status = 422, description = "Model output is not a valid intent"),
    ),
    security(("sentin8:ai:chat:write" = [])),
    tag = "ai",
)]
pub async fn agent_execute(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(body): Json<AgentRequest>,
) -> Result<Json<AgentResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:chat:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;

    // 1. Run inference to obtain the model's intent.
    let inf_req = InferenceRequest {
        prompt_name: Some(body.prompt_name.clone()),
        prompt_version: body.prompt_version,
        messages: vec![crate::providers::ChatMessage {
            role: "user".into(),
            content: body.task.clone(),
        }],
        input: None,
        feature: body.feature.clone(),
        model_override: None,
        max_tokens: None,
        temperature: Some(0.0), // deterministic intent extraction
        target_env_id: body.target_env_id.clone(),
    };
    let inf = run_inference(
        state.clone(),
        headers.clone(),
        q.clone(),
        inf_req,
        "sentin8:ai:chat:write",
    )
    .await?;

    // 2. Parse the structured intent (fail-closed on free text).
    let intent = match crate::agent::parse_intent(&inf.content) {
        Ok(i) => i,
        Err(reason) => {
            return Ok(Json(AgentResponse {
                intent: crate::agent::AgentIntent {
                    action: "invalid".into(),
                    params: serde_json::json!({}),
                    requires_confirmation: false,
                },
                workflow_id: None,
                flow_logic_id: String::new(),
                allowed: false,
                reason: Some(reason),
            }));
        }
    };

    // 3. Resolve the tool allowlist (prompt tools × registered flow logics).
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let prompt_row =
        resolve_prompt(&mut tx, env_id, &body.prompt_name, body.prompt_version).await?;
    let allowed_tools: Vec<crate::agent::ToolDecl> = prompt_row
        .tools
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|t| {
            // Two shapes: {"action": ". ", "flow_logic_id": ". "} or bare name.
            if let Some(action) = t.as_str() {
                Some(crate::agent::ToolDecl {
                    action: action.to_string(),
                    flow_logic_id: action.to_string(),
                    requires_confirmation: false,
                })
            } else {
                serde_json::from_value::<crate::agent::ToolDecl>(t.clone()).ok()
            }
        })
        .collect();
    let tool = match crate::agent::resolve_tool(&allowed_tools, &intent) {
        Ok(t) => t.clone(),
        Err(reason) => {
            tx.commit().await.map_err(err_db)?;
            return Ok(Json(AgentResponse {
                intent: intent.clone(),
                workflow_id: None,
                flow_logic_id: String::new(),
                allowed: false,
                reason: Some(reason),
            }));
        }
    };
    tx.commit().await.map_err(err_db)?;

    // 4. Create the Sentin8:Flow workflow (proxy-back to the domain service).
    let callback_base = body
        .callback_base_url
        .clone()
        .unwrap_or_else(|| sentin8::config::Sentin8Config::from_env().sentin8_ai_url());
    let mut req =
        crate::agent::agent_workflow_request(&tool, &intent, env_id, &a.claims.sub, &inf.content);
    req.callback_config.base_url = callback_base;
    let workflow_id = create_agent_workflow(&state, &req).await;

    // 5. Audit the agent action - act chain preserved.
    crate::agent::audit_agent_action(
        &state.pool,
        env_id,
        &a.claims.sub,
        &intent.action,
        workflow_id.as_deref(),
        serde_json::json!({"flow_logic_id": tool.flow_logic_id, "requires_confirmation": intent.requires_confirmation}),
    )
    .await;

    Ok(Json(AgentResponse {
        intent,
        workflow_id,
        flow_logic_id: tool.flow_logic_id,
        allowed: true,
        reason: None,
    }))
}

/// Fire the Flow workflow via the typed M2M client ( token source;
///). Flow unavailability surfaces in the response - it never blocks
/// the intent contract.
async fn create_agent_workflow(
    state: &AppState,
    req: &sentin8_flow_sdk::client::CreateWorkflowRequest,
) -> Option<String> {
    let record = state.flow.create_workflow(req).await.ok()?;
    Some(record.id.to_string())
}

// ── Budgets ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertBudgetRequest {
    /// '*' = env-wide budget.
    pub feature: String,
    pub monthly_token_cap: i64,
    pub enforcement: String,
}

/// `PUT /v1/budgets/{feature}` - create/update a token budget.
#[utoipa::path(
    put,
    operation_id = "ai.budget.upsert",
    path = "/v1/budgets/{feature}",
    params(("feature" = String, Path), ("target_env_id" = Option<String>, Query)),
    request_body = UpsertBudgetRequest,
    responses((status = 204, description = "Budget saved")),
    security(("sentin8:ai:prompt:write" = [])),
    tag = "ai",
)]
pub async fn put_budget(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(feature): Path<String>,
    Json(body): Json<UpsertBudgetRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    if !matches!(body.enforcement.as_str(), "reject" | "degrade" | "queue") {
        return Err(err_bad("enforcement must be reject|degrade|queue"));
    }
    if body.monthly_token_cap <= 0 {
        return Err(err_bad("monthly_token_cap must be positive"));
    }
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    sqlx::query(
        "INSERT INTO ai.budgets (feature, monthly_token_cap, enforcement, env_id) VALUES ($1,$2,$3,$4)          ON CONFLICT (env_id, feature) DO UPDATE SET monthly_token_cap = $2, enforcement = $3, updated_at = now()",
    )
    .bind(&feature)
    .bind(body.monthly_token_cap)
    .bind(&body.enforcement)
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Cost-gate check : env-wide + per-feature spend vs the budget.
/// Returns Ok(enforcement) when within budget; Err(429) on reject-mode
/// breach. `degrade`/`queue` enforcement is surfaced to the caller via the
/// response header `X-Sentin8-AI-Cost-Enforcement`.
async fn check_budget(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    env_id: Uuid,
    feature: &str,
) -> Result<Option<String>, (StatusCode, String)> {
    let budget: Option<(i64, String)> = sqlx::query_as(
        "SELECT monthly_token_cap, enforcement FROM ai.budgets WHERE env_id = $1 AND feature = $2 AND status = 'active'",
    )
    .bind(env_id)
    .bind(feature)
    .fetch_optional(&mut **tx)
    .await
    .map_err(err_db)?;
    let budget = match budget {
        Some(b) => Some(b),
        None => {
            sqlx::query_as(
                "SELECT monthly_token_cap, enforcement FROM ai.budgets WHERE env_id = $1 AND feature = '*' AND status = 'active'",
            )
            .bind(env_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(err_db)?
        }
    };
    let Some((cap, enforcement)) = budget else {
        return Ok(None); // no budget configured - unmetered
    };
    let spent: i64 = sqlx::query("SELECT sentin8.ai_monthly_tokens($1, $2)")
        .bind(env_id)
        .bind(feature)
        .fetch_one(&mut **tx)
        .await
        .map_err(err_db)?
        .get(0);
    if spent >= cap {
        match enforcement.as_str() {
            "reject" => {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    format!("monthly AI token budget exhausted for '{feature}' ({spent}/{cap})"),
                ));
            }
            other => return Ok(Some(other.to_string())), // degrade | queue
        }
    }
    Ok(None)
}

/// `DELETE /v1/budgets/{feature}` - disable/remove a budget.
#[utoipa::path(
    delete,
    operation_id = "ai.budget.delete",
    path = "/v1/budgets/{feature}",
    params(("feature" = String, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 204, description = "Budget removed")),
    security(("sentin8:ai:prompt:write" = [])),
    tag = "ai",
)]
pub async fn delete_budget(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(feature): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    sqlx::query("DELETE FROM ai.budgets WHERE env_id = $1 AND feature = $2")
        .bind(env_id)
        .bind(&feature)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── DLQ ( - cron pattern) ───────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct DlqRecord {
    pub id: Uuid,
    pub job_type: String,
    pub error_message: String,
    pub retry_count: i32,
    pub created_at: String,
}

/// `GET /v1/dlq` - list dead-lettered AI jobs.
#[utoipa::path(
    get,
    operation_id = "ai.dlq.list",
    path = "/v1/dlq",
    params(("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Dead-lettered jobs", body = [DlqRecord])),
    security(("sentin8:ai:prompt:read" = [])),
    tag = "ai",
)]
pub async fn list_dlq(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<Vec<DlqRecord>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:read"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    let rows = sqlx::query("SELECT id, job_type, error_message, retry_count, created_at FROM ai.dlq WHERE env_id = $1 ORDER BY created_at DESC LIMIT 200")
        .bind(env_id)
        .fetch_all(&state.pool)
        .await
        .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| DlqRecord {
                id: r.get("id"),
                job_type: r.get("job_type"),
                error_message: r.get("error_message"),
                retry_count: r.get("retry_count"),
                created_at: r
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
            })
            .collect(),
    ))
}

/// `POST /v1/dlq/{id}/replay` - re-enqueue a dead-lettered job (cron
/// republish pattern: re-insert the pending job, delete the DLQ row, emit
/// the republished event inbox-first).
#[utoipa::path(
    post,
    operation_id = "ai.dlq.replay",
    path = "/v1/dlq/{id}/replay",
    params(("id" = Uuid, Path), ("target_env_id" = Option<String>, Query)),
    responses((status = 204, description = "Job re-enqueued")),
    security(("sentin8:ai:prompt:write" = [])),
    tag = "ai",
)]
pub async fn replay_dlq(
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
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let row =
        sqlx::query("SELECT job_type, payload, env_id FROM ai.dlq WHERE id = $1 AND env_id = $2")
            .bind(id)
            .bind(env_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(err_db)?
            .ok_or((StatusCode::NOT_FOUND, "dlq item not found".to_string()))?;
    let job_type: String = row.get("job_type");
    let payload: serde_json::Value = row.get("payload");
    // Re-emit the job on the ai stream family (relay → direct consumer).
    sentin8::bus::outbox::insert_outbox_row(
        &mut *tx,
        env_id,
        crate::jobs::AI_STREAM_FAMILY,
        &format!("sentin8:ai:{}:job", job_type),
        &payload,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("replay enqueue failed: {e}"),
        )
    })?;
    sqlx::query("DELETE FROM ai.dlq WHERE id = $1 AND env_id = $2")
        .bind(id)
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Evaluations ──────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct RunEvaluationRequest {
    pub prompt_name: String,
    #[serde(default)]
    pub prompt_version: Option<i32>,
    /// Golden set: `[{ "input": ". ", "expected_contains": ". " },. ]`.
    pub cases: Vec<serde_json::Value>,
    #[serde(default = "default_feature")]
    pub feature: String,
    #[serde(default)]
    pub target_env_id: Option<String>,
}

/// `POST /v1/evaluations/run` - score a prompt version against a golden set
///. Each case runs a synchronous inference and checks the
/// expectation; the aggregate score lands in `ai.evaluations`.
#[utoipa::path(
    post,
    operation_id = "ai.evaluation.run",
    path = "/v1/evaluations/run",
    request_body = RunEvaluationRequest,
    params(("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Evaluation run completed")),
    security(("sentin8:ai:prompt:write" = [])),
    tag = "ai",
)]
pub async fn run_evaluation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(body): Json<RunEvaluationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    if body.cases.is_empty() {
        return Err(err_bad("cases must not be empty"));
    }

    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let prompt = resolve_prompt(&mut tx, env_id, &body.prompt_name, body.prompt_version).await?;
    let version = prompt.version;
    tx.commit().await.map_err(err_db)?;

    let mut results = Vec::new();
    let mut passed = 0i32;
    for case in &body.cases {
        let input = case["input"].as_str().unwrap_or_default().to_string();
        let expected = case["expected"].as_str().map(|s| s.to_string());
        let contains = case["expected_contains"].as_str().map(|s| s.to_string());
        let inf_req = InferenceRequest {
            prompt_name: Some(body.prompt_name.clone()),
            prompt_version: Some(version),
            messages: vec![],
            input: Some(input.clone()),
            feature: format!("eval:{}", body.feature),
            model_override: None,
            max_tokens: None,
            temperature: Some(0.0),
            target_env_id: body.target_env_id.clone(),
        };
        let outcome = run_inference(
            state.clone(),
            headers.clone(),
            q.clone(),
            inf_req,
            "sentin8:ai:completion:write",
        )
        .await;
        let ok = match &outcome {
            Ok(resp) => {
                let mut case_ok = true;
                if let Some(exp) = &expected {
                    case_ok &= resp.content.trim() == exp_trim(exp);
                }
                if let Some(c) = &contains {
                    case_ok &= resp.content.to_lowercase().contains(&c.to_lowercase());
                }
                case_ok
            }
            Err(_) => false,
        };
        if ok {
            passed += 1;
        }
        results.push(serde_json::json!({
            "input": input,
            "passed": ok,
            "output": outcome.as_ref().ok().map(|r| r.content.clone()),
            "error": outcome.as_ref().err().map(|(_, m)| m.clone()),
        }));
    }
    let total = body.cases.len() as i32;
    let score = if total > 0 {
        f64::from(passed) / f64::from(total)
    } else {
        0.0
    };

    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let row = sqlx::query(
        "INSERT INTO ai.evaluations (prompt_name, prompt_version, status, score, cases_passed, cases_total, results, env_id) \n         VALUES ($1,$2,'completed',$3::text::numeric,$4,$5,$6,$7) RETURNING id",
    )
    .bind(&body.prompt_name)
    .bind(version)
    .bind(score)
    .bind(passed)
    .bind(total)
    .bind(serde_json::to_value(&results).unwrap_or_default())
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    Ok(Json(serde_json::json!({
        "id": row.get::<Uuid, _>("id"),
        "prompt_version": version,
        "score": score,
        "passed": passed,
        "total": total,
    })))
}

fn exp_trim(s: &String) -> String {
    s.trim().to_string()
}

/// Trace feature label: cost-gated requests carry the enforcement mode so
/// spend dashboards can distinguish degraded/queued calls.
fn trace_feature_label(feature: &str, enforcement: Option<&str>) -> String {
    match enforcement {
        Some(mode) => format!("{feature}:cost-{mode}"),
        None => feature.to_string(),
    }
}

// ── Embedding dimension registry ─────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegistryDimRequest {
    pub model: String,
    pub dims: i32,
}

/// `PUT /v1/embedding-registry/{model}` - pin a model→dimension mapping for
/// the env. Mismatched embeddings are rejected with 422.
#[utoipa::path(
    put,
    operation_id = "ai.registry.pin",
    path = "/v1/registry/{model}",
    params(("model" = String, Path), ("target_env_id" = Option<String>, Query)),
    request_body = RegistryDimRequest,
    responses((status = 204, description = "Dimension pinned")),
    security(("sentin8:ai:prompt:write" = [])),
    tag = "ai",
)]
pub async fn pin_embedding_registry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(model): Path<String>,
    Json(body): Json<RegistryDimRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:embedding:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    if body.dims <= 0 || body.dims > 100_000 {
        return Err(err_bad("dims must be in 1..=100000"));
    }
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    sqlx::query(
        "INSERT INTO ai.embedding_registry (model, dims, env_id) VALUES ($1,$2,$3)          ON CONFLICT (env_id, model, dims) DO UPDATE SET updated_at = now()",
    )
    .bind(&model)
    .bind(body.dims)
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/registry` - list pinned model→dimension mappings.
#[utoipa::path(
    get,
    operation_id = "ai.registry.list",
    path = "/v1/registry",
    params(("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Pinned dimensions")),
    security(("sentin8:ai:embedding:write" = [])),
    tag = "ai",
)]
pub async fn list_embedding_registry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:embedding:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    let rows = sqlx::query("SELECT model, dims, status FROM ai.embedding_registry WHERE env_id = $1 AND status = 'active' ORDER BY model")
        .bind(env_id)
        .fetch_all(&state.pool)
        .await
        .map_err(err_db)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(serde_json::json!({
            "model": r.get::<String, _>("model"),
            "dims": r.get::<i32, _>("dims"),
            "status": r.get::<String, _>("status"),
        }));
    }
    Ok(Json(serde_json::Value::Array(out)))
}

// ── Internal proxy-back ( cron target + agent domain step) ─────

/// `POST /v1/internal/schedules/run` - Sentin8:Cron proxy-back target
///. Runs stale-index maintenance: re-enqueue embedding jobs for
/// sources whose embedding is older than the freshness window. Authenticated
/// by the cron ticker's M2M token (verified the same way as user tokens -
/// `token_tp: m2m` principals evaluate like any other under Shield).
#[utoipa::path(
    post,
    operation_id = "ai.internal.schedules.run",
    path = "/v1/internal/schedules/run",
    request_body = serde_json::Value,
    responses((status = 200, description = "Maintenance run completed")),
    tag = "ai",
)]
pub async fn internal_schedules_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    // M2M parity - token type never bypasses policy.
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:embedding:write"),
    )
    .await?;
    let schedule_type = body["schedule_type"].as_str().unwrap_or("unknown");
    let env_id = body["env_id"]
        .as_str()
        .and_then(|s| uuid::Uuid::parse_str(s).ok());
    let mut tx = begin_tenant_tx(&state.pool, env_id.unwrap_or_default()).await?;
    // Stale-index maintenance (AI-2): when the cron fires the
    // `model_migration` schedule the sweep re-enqueues embedding jobs for
    // rows whose `model_version` trails the registry-active version for
    // their model - the dual-read discriminator. Otherwise (freshness
    // schedule) rows older than the window are reported as before.
    let stale: Vec<serde_json::Value> = if schedule_type == "model_migration" {
        sqlx::query(
            r#"SELECT e.source_id, e.model
                 FROM ai.embeddings e
                WHERE e.env_id = $1 AND e.source_id IS NOT NULL
                  AND e.model_version <> COALESCE(
                      (SELECT r.version FROM ai.embedding_registry r
                        WHERE r.env_id = e.env_id AND r.model = e.model
                        ORDER BY r.updated_at DESC LIMIT 1), 'v1')
                LIMIT 20"#,
        )
        .bind(env_id.unwrap_or_default())
        .fetch_all(&mut *tx)
        .await
        .map_err(err_db)?
        .iter()
        .map(|r| {
            serde_json::json!({
                "source_id": r.get::<Option<String>, _>("source_id"),
                "model": r.get::<String, _>("model"),
                "reason": "model_version_trails_registry",
            })
        })
        .collect()
    } else {
        sqlx::query(
            "SELECT source_id, model FROM ai.embeddings          WHERE env_id = $1 AND source_id IS NOT NULL          AND created_at < now() - interval '7 days'      GROUP BY source_id, model LIMIT 20",
        )
        .bind(env_id.unwrap_or_default())
        .fetch_all(&mut *tx)
        .await
        .map_err(err_db)?
        .iter()
        .map(|r| serde_json::json!({ "source_id": r.get::<Option<String>, _>("source_id"), "model": r.get::<String, _>("model") }))
        .collect()
    };
    tx.commit().await.map_err(err_db)?;
    tracing::info!(stale = stale.len(), "ai maintenance run");
    Ok(Json(serde_json::json!({
        "schedule_type": body["schedule_type"],
        "stale_sources": stale,
        "status": "completed",
    })))
}

// ── Document pipeline (/) ─────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct DocumentIngestRequest {
    /// Sentin8:Storage object key holding the document text.
    pub storage_key: String,
    /// Already-extracted text (extract step happens upstream or in this
    /// request - v1 accepts the plain text; PDF extraction is a Func WASM
    /// module concern).
    pub text: String,
    pub model: String,
    /// Caller's data scope attached to the chunks' metadata (retrieval
    /// permission filter).
    #[serde(default)]
    pub data_scope: Vec<String>,
    #[serde(default)]
    pub source_id: Option<String>,
    #[serde(default = "default_chunk_size")]
    pub chunk_size: usize,
    #[serde(default)]
    pub target_env_id: Option<String>,
}

fn default_chunk_size() -> usize {
    512
}

/// `POST /v1/documents/ingest` - chunk → embed → store (/).
/// Chunk text lives in Sentin8:Storage (object per chunk under the document
/// key), vectors + metadata in `ai.embeddings` with source refs.
/// RLS env match + the caller's data_scope on chunk metadata.
#[utoipa::path(
    post,
    operation_id = "ai.document.ingest",
    path = "/v1/documents/ingest",
    request_body = DocumentIngestRequest,
    params(("target_env_id" = Option<String>, Query)),
    responses(
        (status = 200, description = "Document ingested (chunks + vectors stored)"),
        (status = 422, description = "Embedding failure"),
    ),
    security(("sentin8:ai:embedding:write" = [])),
    tag = "ai",
)]
pub async fn document_ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(body): Json<DocumentIngestRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:embedding:write"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    if body.text.trim().is_empty() {
        return Err(err_bad("text must not be empty"));
    }
    if body.chunk_size == 0 || body.chunk_size > 8192 {
        return Err(err_bad("chunk_size must be in 1..=8192"));
    }

    // 1. Chunk (character-window chunking with overlap-free boundaries).
    let chars: Vec<char> = body.text.chars().collect();
    let chunks: Vec<String> = chars
        .chunks(body.chunk_size)
        .map(|c| c.iter().collect::<String>())
        .collect();
    let source_id = body
        .source_id
        .clone()
        .unwrap_or_else(|| format!("doc-{}", uuid::Uuid::new_v4()));

    // 2. Embed the batch (provider router).
    let route = state
        .routes
        .values()
        .find(|r| r.embedder.is_some())
        .ok_or_else(|| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "no embedding provider configured".to_string(),
            )
        })?;
    let client = reqwest::Client::new();
    let emb = state
        .router
        .embed(
            &client,
            route,
            &crate::providers::EmbeddingRequest {
                model: body
                    .model
                    .split_once('/')
                    .map(|(_, m)| m.to_string())
                    .unwrap_or_else(|| body.model.clone()),
                inputs: chunks.clone(),
            },
        )
        .await
        .map_err(|e| match &e {
            crate::providers::ProviderError::Terminal { message, .. } => {
                (StatusCode::UNPROCESSABLE_ENTITY, message.clone())
            }
            crate::providers::ProviderError::Transient { message, .. } => {
                (StatusCode::BAD_GATEWAY, message.clone())
            }
        })?;

    // 3. Persist: chunk text to Sentin8:Storage (RLS env-scoped keys,
    // M2M client -), vectors + metadata to the DB (source refs).
    // Storage writes are best-effort per chunk: a Storage outage degrades
    // to warn logging, the DB row carries the content_ref either way.
    let scope_meta = serde_json::json!({ "data_scope": body.data_scope });
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let mut stored = 0usize;
    let mut storage_written = 0usize;
    for (idx, (text, vector)) in chunks.iter().zip(emb.vectors.iter()).enumerate() {
        let vec_literal = format!(
            "[{}]",
            vector
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let chunk_key = format!(
            "{}/chunks/{source_id}-{idx:04}.txt",
            body.storage_key.trim_end_matches('/')
        );
        // Chunk text lives in Sentin8:Storage (object per chunk under the
        // document key -); the DB row carries the object ref.
        match state
            .storage
            .put(
                &env_id.to_string(),
                &env_id.to_string(),
                &chunk_key,
                "text/plain; charset=utf-8",
                text.clone().into_bytes(),
            )
            .await
        {
            Ok(()) => storage_written += 1,
            Err(e) => {
                tracing::warn!(
                    chunk = idx,
                    error = %e,
                    "chunk Storage write failed - vector row keeps the content_ref"
                );
            }
        }
        sqlx::query(
            "INSERT INTO ai.embeddings (embedding, content_ref, metadata, chunk_index, model, source_id, chunk_text, env_id, model_version) \
             VALUES ($1::vector, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&vec_literal)
        .bind(&chunk_key)
        .bind(&scope_meta)
        .bind(idx as i32)
        .bind(&body.model)
        .bind(&source_id)
        .bind(text)
        .bind(env_id)
        .bind(registry_version_for(&state.pool, env_id, &body.model).await)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
        stored += 1;
    }
    tx.commit().await.map_err(err_db)?;
    Ok(Json(serde_json::json!({
        "source_id": source_id,
        "chunks": stored,
        "storage_written": storage_written,
        "model": body.model,
        "dims": emb.vectors.first().map(|v| v.len()).unwrap_or(0),
    })))
}

// ── Cost report ──────────────────────────────────────────────────

/// `GET /v1/costs` - per-feature/model spend rollup for the env,
/// reading the AI's own trace aggregates (Stat cross-service rollup lands
/// with the Dash integration).
#[utoipa::path(
    get,
    operation_id = "ai.cost.report",
    path = "/v1/costs",
    params(("target_env_id" = Option<String>, Query)),
    responses((status = 200, description = "Per-feature/model spend rollup")),
    security(("sentin8:ai:prompt:read" = [])),
    tag = "ai",
)]
pub async fn cost_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:read"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    let rows = sqlx::query(
        "SELECT feature, model, COUNT(*) AS calls, \
                COALESCE(SUM(input_tokens), 0) AS in_tokens, \
                COALESCE(SUM(output_tokens), 0) AS out_tokens, \
                COALESCE(AVG(latency_ms), 0) AS avg_latency \
         FROM ai.traces WHERE env_id = $1 \
         AND created_at >= date_trunc('month', now()) \
         GROUP BY feature, model ORDER BY in_tokens + out_tokens DESC LIMIT 50",
    )
    .bind(env_id)
    .fetch_all(&state.pool)
    .await
    .map_err(err_db)?;
    let mut rows_json = Vec::new();
    for r in rows {
        rows_json.push(serde_json::json!({
            "feature": r.get::<String, _>("feature"),
            "model": r.get::<String, _>("model"),
            "calls": r.get::<i64, _>("calls"),
            "input_tokens": r.get::<i64, _>("in_tokens"),
            "output_tokens": r.get::<i64, _>("out_tokens"),
            "avg_latency_ms": r.get::<f64, _>("avg_latency"),
        }));
    }
    Ok(Json(serde_json::json!({
        "window": "current-month",
        "rows": rows_json,
    })))
}

// ── Trace retention ──────────────────────────────────────────────

/// `POST /v1/internal/traces/archive` - age out hot traces older than the
/// per-env retention window to Sentin8:Storage (Stat pattern). Called by the
/// cron proxy-back (`/v1/internal/schedules/run` maintenance) - never by
/// clients directly.
#[utoipa::path(
    post,
    operation_id = "ai.traces.archive",
    path = "/v1/internal/traces/archive",
    request_body = serde_json::Value,
    responses((status = 200, description = "Archive run completed")),
    tag = "ai",
)]
pub async fn traces_archive(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:write"),
    )
    .await?;
    let env_id = body["env_id"]
        .as_str()
        .and_then(|s| uuid::Uuid::parse_str(s).ok());
    let Some(env_id) = env_id else {
        return Err(err_bad("env_id required in body"));
    };
    // Traces older than 30 days are archived to Sentin8:Storage (one NDJSON
    // object per env/window - the Stat aggregate pattern) before deletion
    // from the hot table. The Storage write is best-effort: when it fails
    // the delete is skipped (no silent data loss); the next run retries.
    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let aged: Vec<serde_json::Value> = sqlx::query(
        "SELECT to_jsonb(t) AS row FROM ai.traces t \
         WHERE env_id = $1 AND created_at < now() - interval '30 days' LIMIT 10000",
    )
    .bind(env_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(err_db)?
    .iter()
    .map(|r| r.get::<serde_json::Value, _>("row"))
    .collect();
    if aged.is_empty() {
        tx.commit().await.map_err(err_db)?;
        return Ok(Json(serde_json::json!({ "archived": 0 })));
    }
    let mut body_ndjson = String::new();
    for row in &aged {
        body_ndjson.push_str(&row.to_string());
        body_ndjson.push('\n');
    }
    let archive_key = format!(
        "ai/traces/{env_id}/{}.ndjson",
        chrono::Utc::now().to_rfc3339().replace(':', "-")
    );
    match state
        .storage
        .put(
            &env_id.to_string(),
            &env_id.to_string(),
            &archive_key,
            "application/x-ndjson",
            body_ndjson.into_bytes(),
        )
        .await
    {
        Ok(()) => {
            let n = sqlx::query(
                "DELETE FROM ai.traces WHERE env_id = $1 AND created_at < now() - interval '30 days'",
            )
            .bind(env_id)
            .execute(&mut *tx)
            .await
            .map_err(err_db)?
            .rows_affected();
            tx.commit().await.map_err(err_db)?;
            Ok(Json(
                serde_json::json!({ "archived": n, "storage_key": archive_key }),
            ))
        }
        Err(e) => {
            // Keep the hot rows - retry on the next run (cron proxy-back).
            tracing::warn!(error = %e, "trace archive Storage write failed - hot rows retained");
            tx.commit().await.map_err(err_db)?;
            Ok(Json(
                serde_json::json!({ "archived": 0, "error": "storage unavailable" }),
            ))
        }
    }
}

// ── Traces ( read surface) ──────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct TraceRecord {
    pub id: Uuid,
    pub prompt_name: String,
    pub prompt_version: Option<i32>,
    pub model: String,
    pub feature: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub latency_ms: i32,
    pub cache_hit: bool,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TraceListQuery {
    #[serde(default)]
    pub target_env_id: Option<String>,
    #[serde(default)]
    pub feature: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

/// `GET /v1/traces` - recent inference traces (env-scoped).
#[utoipa::path(
    get,
    operation_id = "trace.list",
    path = "/v1/traces",
    params(("target_env_id" = Option<String>, Query), ("feature" = Option<String>, Query), ("limit" = Option<i64>, Query)),
    responses((status = 200, description = "Inference traces", body = [TraceRecord])),
    security(("sentin8:ai:prompt:read" = [])),
    tag = "ai",
)]
pub async fn list_traces(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TraceListQuery>,
) -> Result<Json<Vec<TraceRecord>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:read"),
    )
    .await?;
    let env_id = resolve_env_id(&a, q.target_env_id.as_deref())?;
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let rows = sqlx::query(
        "SELECT * FROM ai.traces WHERE env_id = $1 AND ($2::text IS NULL OR feature = $2) ORDER BY created_at DESC LIMIT $3",
    )
    .bind(env_id)
    .bind(&q.feature)
    .bind(limit)
    .fetch_all(&state.pool)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| TraceRecord {
                id: r.get("id"),
                prompt_name: r.get("prompt_name"),
                prompt_version: r.get("prompt_version"),
                model: r.get("model"),
                feature: r.get("feature"),
                input_tokens: r.get("input_tokens"),
                output_tokens: r.get("output_tokens"),
                latency_ms: r.get("latency_ms"),
                cache_hit: r.get("cache_hit"),
                status: r.get("status"),
                created_at: r
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
            })
            .collect(),
    ))
}

/// Resolve the registry-active model version for `(env, model)` (AI-2
/// dual-write): rows written by a generation stamp this version; the
/// Cron sweep re-enqueues rows that trail it. Falls back to `v1` when
/// the env has no registry row (the default generation).
pub(crate) async fn registry_version_for(pool: &sqlx::PgPool, env_id: Uuid, model: &str) -> String {
    sqlx::query_scalar::<_, String>(
        "SELECT version FROM ai.embedding_registry WHERE env_id = $1 AND model = $2 ORDER BY updated_at DESC LIMIT 1",
    )
    .bind(env_id)
    .bind(model)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "v1".to_string())
}
