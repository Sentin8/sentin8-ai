// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for AI.

use std::sync::Arc;

use axum::routing::{get, post, put};
use serde_json::json;

use crate::handlers::{self, AppState};
use crate::providers::ProviderRouter;

pub async fn build_state(
    core: sentin8::shell::ServiceCore,
) -> anyhow::Result<crate::handlers::AppState> {
    let config = crate::config::AiConfig::from_env();

    // ── Sentin8:Policy (shell-owned boot): the shell's
    // boot step 8 already loaded the engine (refuse-to-start on invalid
    // policy text), init'd the shared step-5 deps, spawned the hot-reload
    // consumer and the stat emitter. Services only CONSUME the engine -
    // booting a second one here would duplicate the bus consumer + DCR
    // registration and risk a cache split with the admin API.
    let policy_engine = core.admin.policy.clone();

    // ── Provider routes are TENANT configuration (ai DESIGN.md §4.5).
    // The cache resolves `(env, provider)` on demand and invalidates on
    // `sentin8:ai:provider:updated`, so a tenant registration takes effect
    // on the next request instead of requiring a restart.
    let route_cache = Arc::new(crate::provider_routes::ProviderRouteCache::default());

    // Seed the platform default eagerly so the first request in a fresh env
    // does not pay two lookups, and so `/v1/health` can report readiness.
    if let Some(platform_env) = sentin8_system_env_id_opt(&core.pool).await {
        for provider in ["openai", "anthropic", "ollama", "vllm"] {
            let _ = route_cache.resolve(&core.pool, platform_env, provider).await;
        }
    }

    // ── Async AI jobs - direct embedding consumer (the `ai`
    // workload CERTIFICATE is the identity; Bus's TLS layer authenticates
    // the handshake - no DCR, no token). The mint retries while Acme comes
    // up (boot window); the consumers' reconnect loops cover a late
    // identity.
    let bus_client = loop {
        match sentin8::bus::client::BusClient::for_workload(
            &config.bus_url,
            &config.sentin8_auth_issuer,
            "ai",
        )
        .await
        {
            Ok(c) => break c,
            Err(e) => {
                tracing::debug!(error = %e, "AI bus client: certificate not ready yet");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    };

    // ── Outbound identity (auth DESIGN §4.3f) - the
    // `ai-proxy` CERTIFICATE is the identity: ensure it once (load-or-mint
    // from Acme) and build the cert-presenting Storage + Flow clients.
    // Every failure degrades to a plain-transport warn - never a boot
    // refusal (the platform may not be up yet).
    let ai_cert = sentin8::auth::m2m::ensure_workload_certificate(
        &config.sentin8_auth_issuer,
        "ai-proxy",
        &sentin8::auth::m2m::platform_ca_path(),
    )
    .await;
    if let Err(e) = &ai_cert {
        tracing::warn!(error = %e, "AI outbound certificate not ready - Storage/Flow degrade to plain transports until next boot");
    }

    let cfg_platform = sentin8::config::Sentin8Config::from_env();

    // Cert-presenting Storage client - chunk writes + trace archive.
    let storage_client = match &ai_cert {
        Ok(cert) => sentin8_storage_sdk::client::StorageClient::with_workload_identity(
            cfg_platform.sentin8_storage_url(),
            &cert.ca_cert_path,
            &cert.cert_path,
            &cert.key_path,
        )
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "AI Storage client transport build failed - dev plain fallback");
            sentin8_storage_sdk::client::StorageClient::new_dev_plain(cfg_platform.sentin8_storage_url())
        }),
        Err(_) => sentin8_storage_sdk::client::StorageClient::new_dev_plain(cfg_platform.sentin8_storage_url()),
    };

    // Cert-presenting Flow client - agent workflow creation.
    let flow_client = match &ai_cert {
        Ok(cert) => sentin8_flow_sdk::client::FlowClient::with_workload_identity(
            cfg_platform.sentin8_flow_url(),
            &cert.ca_cert_path,
            &cert.cert_path,
            &cert.key_path,
        )
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "AI Flow client transport build failed - dev plain fallback");
            sentin8_flow_sdk::client::FlowClient::new_dev_plain(cfg_platform.sentin8_flow_url())
        }),
        Err(_) => sentin8_flow_sdk::client::FlowClient::new_dev_plain(cfg_platform.sentin8_flow_url()),
    };

    // ── Inference metrics publish via the shared MemBus telemetry path
    // (SDD §2.6): the shell boot initialized the emitter (slug `ai`);
    // emission is fire-and-forget, log-only on failure.

    // Cert-presenting Func client - `func_module` tools. Boot-soft: a
    // missing certificate leaves `func` as `None` and the gateway denies
    // those tools with an explicit reason rather than failing startup.
    let func_client = match (&ai_cert, cfg_platform.sentin8_func_url()) {
        (Ok(_), url) if !url.is_empty() => {
            match sentin8::auth::m2m::ensure_workload_certificate(
                &config.sentin8_auth_issuer,
                "ai-proxy",
                &sentin8::auth::m2m::platform_ca_path(),
            )
            .await
            {
                Ok(cert) => sentin8_func_sdk::client::FuncClient::with_workload_identity(
                    url,
                    &cert.ca_cert_path,
                    &cert.cert_path,
                    &cert.key_path,
                )
                .ok(),
                Err(e) => {
                    tracing::warn!(error = %e, "AI Func client: certificate not ready - func_module tools unavailable until next boot");
                    None
                }
            }
        }
        _ => None,
    };

    let router_arc = std::sync::Arc::new(ProviderRouter::default());
    let storage_for_jobs = storage_client.clone();

    let state = AppState {
        config: Arc::new(config.clone()),
        pool: core.pool.clone(),
        policy: policy_engine.clone(),
        admin: sentin8::shield::admin::SharedAdminState {
            service: "sentin8:ai".to_string(),
            pool: core.pool.clone(),
            policy: policy_engine.clone(),
            auth_client: Arc::new(config.auth_client.clone()),
        },
        router: std::sync::Arc::clone(&router_arc),
        routes: Arc::clone(&route_cache),
        storage: storage_client,
        flow: flow_client,
        func: func_client,
    };
    crate::jobs::spawn_embedding_consumer(
        core.pool.clone(),
        bus_client.clone(),
        Arc::clone(&route_cache),
        std::sync::Arc::clone(&router_arc),
    );
    crate::jobs::spawn_summary_consumer(
        core.pool.clone(),
        bus_client.clone(),
        Arc::clone(&route_cache),
        std::sync::Arc::clone(&router_arc),
    );
    // Document pipeline - document.uploaded → Storage fetch →
    // chunk → embed → persist.
    crate::jobs::spawn_document_consumer(
        core.pool.clone(),
        bus_client,
        Arc::clone(&route_cache),
        router_arc,
        storage_for_jobs,
    );
    // Maintenance schedules (SDD §2.4) are declarative - the
    // registration's `schedules` section provisions them at enroll
    // time; ai makes no boot-time cron calls.
    Ok(state)
}

/// The platform system env (sys/ops) owns the DEFAULT provider routes - an
/// env without its own provider row falls back to it. Returns `None` when
/// bootstrap has not yet applied (boot proceeds with an empty default).
async fn sentin8_system_env_id_opt(pool: &sqlx::PgPool) -> Option<uuid::Uuid> {
    match sqlx::query_scalar(
        "SELECT e.id FROM sys.environments e \
         JOIN sys.organizations o ON o.id = e.org_id \
         WHERE o.slug = 'sys' AND e.slug = 'ops' LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    {
        Ok(id) => id,
        // A real SQL failure must be LOUD, not silently treated as
        // "bootstrap not applied" (the old `.ok` swallowed the
        // wrong-column error and mislabeled it as a missing env).
        Err(e) => {
            tracing::error!(error = %e, "sys/ops env lookup failed - no platform provider default");
            None
        }
    }
}

/// The platform system env, with the nil-UUID fallback used by callers that
/// need a value (never for provider routing).
async fn sentin8_system_env_id(pool: &sqlx::PgPool) -> uuid::Uuid {
    sentin8_system_env_id_opt(pool).await.unwrap_or_else(|| {
        tracing::warn!("sys/ops env not found - using nil env");
        uuid::Uuid::nil()
    })
}

/// Add this service's routes onto the shell-provided router. The shell
/// owns the boot sequence, state binding, OpenAPI merge and the standard
/// middleware stack; this adds ONLY routes (including the service's own
/// `/v1/health` - custom payload).
pub fn routes(
    router: axum::Router<crate::handlers::AppState>,
) -> axum::Router<crate::handlers::AppState> {
    router
        .route("/v1/health", get(handlers::health))
        // ── Prompt registry ────────────────────────────────────────
        .route(
            "/v1/prompts",
            post(handlers::create_prompt).get(handlers::list_prompts),
        )
        .route(
            "/v1/prompts/{name}/{version}",
            axum::routing::delete(handlers::delete_prompt),
        )
        // ── Inference primitives ───────────────────────────────────
        .route("/v1/chat", post(handlers::chat))
        .route("/v1/chat/stream", post(handlers::chat_stream))
        .route("/v1/completions", post(handlers::completions))
        .route("/v1/embeddings", post(handlers::embeddings))
        // ── Providers ────────────────────────────────────────────
        .route("/v1/providers", get(handlers::list_providers))
        .route(
            "/v1/providers/{provider}",
            put(handlers::put_provider).delete(handlers::delete_provider),
        )
        // ── Retrieval ──────────────────────────────────────────────
        .route("/v1/retrieval", post(handlers::retrieval))
        // ── Agent runtime (§4.1) ───────────────────────────────────
        .route("/v1/agent/execute", post(handlers::agent_execute))
        // Conversations (the multi-turn transcript plane)
        .route(
            "/v1/conversations",
            post(crate::conversation::create_conversation)
                .get(crate::conversation::list_conversations),
        )
        .route(
            "/v1/conversations/{id}",
            get(crate::conversation::get_conversation)
                .put(crate::conversation::update_conversation),
        )
        .route(
            "/v1/conversations/{id}/messages",
            get(crate::conversation::list_messages),
        )
        // Turns - one bounded agent turn
        .route(
            "/v1/conversations/{id}/turns",
            post(crate::conversation::post_turn),
        )
        .route("/v1/runs/{id}", get(crate::conversation::get_run))
        .route("/v1/runs/{id}/cancel", post(crate::conversation::cancel_run))
        // Tools (the tenant-authorable capability registry)
        .route("/v1/tools", get(crate::conversation::list_tools))
        .route(
            "/v1/tools/{name}",
            put(crate::conversation::put_tool).delete(crate::conversation::delete_tool),
        )
        // Agents + policies
        .route("/v1/agents", get(crate::conversation::list_agents))
        .route(
            "/v1/agents/{name}",
            put(crate::conversation::put_agent).delete(crate::conversation::delete_agent),
        )
        .route("/v1/agent-policies", get(crate::conversation::list_policies))
        .route(
            "/v1/agent-policies/{name}",
            put(crate::conversation::put_policy),
        )
        // Human approval for irreversible tool actions
        .route("/v1/approvals", get(crate::conversation::list_approvals))
        .route(
            "/v1/approvals/{id}/decide",
            post(crate::conversation::decide_approval),
        )
        // ── Budgets ──────────────────────────────────────────────
        .route(
            "/v1/budgets/{feature}",
            put(handlers::put_budget).delete(handlers::delete_budget),
        )
        // POST alias for RFW row_action_post (renderer only supports POST)
        .route(
            "/v1/budgets/{feature}/delete",
            post(crate::ai_aliases::budget_delete),
        )
        // ── DLQ ──────────────────────────────────────────────────
        .route("/v1/dlq", get(handlers::list_dlq))
        .route("/v1/dlq/{id}/replay", post(handlers::replay_dlq))
        // ── Evaluations ──────────────────────────────────────────
        .route("/v1/evaluations/run", post(handlers::run_evaluation))
        // ── Embedding dimension registry ─────────────────────────
        .route("/v1/registry", get(handlers::list_embedding_registry))
        .route(
            "/v1/registry/{model}",
            put(handlers::pin_embedding_registry),
        )
        // ── Document pipeline (/4) ──────────────────────────────────
        .route("/v1/documents/ingest", post(handlers::document_ingest))
        // ── Safety filters ( - env-configurable rules) ─────────────
        // (The PUT /v1/filters/{name} form is the upsert; the collection
        // POST bound here previously was unreachable-by-contract - the
        // handler's Path(name) can never extract on a segment-less route
        // (axum rejects with 500) and no consumer exists. Deleted per
        // OAPEC: a served route must be a working contract.)
        .route("/v1/filters", get(handlers::list_filters))
        .route(
            "/v1/filters/{name}",
            put(handlers::put_filter).delete(handlers::delete_filter),
        )
        // POST alias for RFW row_action_post (renderer only supports POST)
        .route(
            "/v1/filters/{name}/delete",
            post(crate::ai_aliases::filter_delete),
        )
        // ── Cost report ──────────────────────────────────────────
        .route("/v1/costs", get(handlers::cost_report))
        // ── Trace retention (internal) ────────────────────────────
        .route(
            "/v1/internal/traces/archive",
            post(handlers::traces_archive),
        )
        // ── Internal proxy-back ( cron target) ─────────────────────
        .route(
            "/v1/internal/schedules/run",
            post(handlers::internal_schedules_run),
        )
        // ── Internal agent step execution (Flow proxy-back) ─────────
        // Flow's domain-step transport POSTs `{internal_path}/execute`, so
        // the agent runtime's legacy JSON-intent path addresses
        // `/v1/internal/agent` (ai DESIGN.md §4.1).
        .route(
            "/v1/internal/agent/execute",
            post(crate::conversation::internal_agent_step),
        )
        // ── Admin UI (RFW - /) ───────────────────────────────
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        .route("/v1/admin/{resource}", get(crate::admin_ui::get_admin_data))
        // ── Traces ───────────────────────────────────────────────
        .route("/v1/traces", get(handlers::list_traces))
        // ── Sentin8:Policy admin API ( shared implementation,
        // one surface per service; handlers are generic over this AppState).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<handlers::AppState>),
        )
}

/// Shared policy-admin surface accessor - the shared
/// handlers extract this service's admin state via [`HasPolicyAdmin`].
impl sentin8::shield::admin::HasPolicyAdmin for AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}

/// Registration parity probe used by tests: the state built from a core
/// must carry the colon identity of the registration output.
pub fn registration_service_type() -> serde_json::Value {
    json!({ "service_type": "sentin8:ai", "subdomain": "ai" })
}
