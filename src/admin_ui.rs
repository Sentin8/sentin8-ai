// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! RFW admin UI for Sentin8:AI ( /) — mirrors the cron/func
//! pattern. The service owns its admin pages; the dash is a pure rendering
//! host (architecture-).

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;

use crate::auth;
use sqlx::Row;

use crate::handlers::{AppState, TargetEnvQuery};

/// `GET /v1/admin/ui/{page}` — RFW definition for the page.
#[utoipa::path(
    get,
    operation_id = "ai.admin.ui",
    path = "/v1/admin/ui/{page}",
    params(("page" = String, Path)),
    responses((status = 200, description = "RFW page definition")),
    tag = "ai",
)]
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(_q): Query<TargetEnvQuery>,
    Path(page): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    // Step 5 (Shield) is enforced on the data endpoints; the definitions are
    // static — verification here only (cheap), enforcement on data reads.
    let def = match page.as_str() {
        "prompts" => AdminPage::new("Prompt Registry")
            .action(link("New Prompt Version", "prompts/new"))
            .widget(table_with_actions(
                vec![
                    cols("name", "Prompt"),
                    cols("version", "Version"),
                    cols("model_primary", "Primary Model"),
                    cols("status", "Status"),
                    cols("origin", "Origin"),
                ],
                "/admin/prompts",
                vec![
                    row_action_post("Pin", "prompts/{id}/pin"),
                    row_action_post("Retire", "prompts/{id}/delete"),
                ],
            ))
            .build(),
        "prompts/new" => AdminPage::new("Create Prompt Version")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    field_text("name", "Prompt Name", true),
                    field_number("version", "Version", true),
                    field_textarea("system_text", "System Instructions", true),
                    field_textarea("user_text", "User Template", false),
                    field_text("model_primary", "Primary Model (openai/gpt-5)", true),
                    field_text("model_fallback", "Fallback Model", false),
                    field_number("temperature", "Temperature", false),
                    field_number("max_tokens", "Max Tokens", false),
                ],
                submit_endpoint: "/v1/prompts".into(),
                submit_label: "Create Version".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        "providers" => AdminPage::new("Model Providers")
            .action(link("Add Provider", "providers/new"))
            .widget(table_with_actions(
                vec![
                    cols("provider", "Provider"),
                    cols("base_url", "Base URL"),
                    cols("credential_ref", "Credential Ref"),
                    cols("status", "Status"),
                ],
                "/admin/providers",
                vec![row_action_post("Disable", "providers/{id}/delete")],
            ))
            .build(),
        "providers/new" => AdminPage::new("Add Provider")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    select_field(
                        "provider",
                        "Provider",
                        vec![
                            ("openai", "OpenAI"),
                            ("anthropic", "Anthropic"),
                            ("ollama", "Ollama Cloud"),
                            ("vllm", "Self-hosted (vLLM)"),
                        ],
                    ),
                    field_text("base_url", "Base URL", true),
                    field_text("credential_ref", "Credential Secret Reference", true),
                ],
                submit_endpoint: "/v1/providers-config".into(),
                submit_label: "Save Provider".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        "traces" => AdminPage::new("Inference Traces")
            .widget(table_with_actions(
                vec![
                    cols("prompt_name", "Prompt"),
                    cols("model", "Model"),
                    cols("feature", "Feature"),
                    cols("input_tokens", "In Tokens"),
                    cols("output_tokens", "Out Tokens"),
                    cols("latency_ms", "Latency (ms)"),
                    cols("cache_hit", "Cache"),
                ],
                "/admin/traces",
                vec![],
            ))
            .build(),
        "budgets" => AdminPage::new("Token Budgets")
            .action(link("New Budget", "budgets/new"))
            .widget(table_with_actions(
                vec![
                    cols("feature", "Feature"),
                    cols("monthly_token_cap", "Monthly Cap"),
                    cols("enforcement", "Enforcement"),
                    cols("status", "Status"),
                ],
                "/admin/budgets",
                vec![row_action_post("Disable", "budgets/{id}/delete")],
            ))
            .build(),
        "budgets/new" => AdminPage::new("Create Budget")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    field_text("feature", "Feature ('*' = env-wide)", true),
                    field_number("monthly_token_cap", "Monthly Token Cap", true),
                    select_field(
                        "enforcement",
                        "Enforcement",
                        vec![
                            ("reject", "Reject"),
                            ("degrade", "Degrade"),
                            ("queue", "Queue"),
                        ],
                    ),
                ],
                submit_endpoint: "/v1/budgets".into(),
                submit_label: "Create Budget".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        "dlq" => AdminPage::new("Embedding Job DLQ")
            .widget(table_with_actions(
                vec![
                    cols("job_type", "Job Type"),
                    cols("error_message", "Error"),
                    cols("retry_count", "Retries"),
                ],
                "/admin/dlq",
                vec![row_action_post("Replay", "dlq/{id}/replay")],
            ))
            .build(),
        "evaluations" => AdminPage::new("Prompt Evaluations")
            .widget(table_with_actions(
                vec![
                    cols("prompt_name", "Prompt"),
                    cols("prompt_version", "Version"),
                    cols("status", "Status"),
                    cols("score", "Score"),
                    cols("cases_passed", "Passed"),
                    cols("cases_total", "Total"),
                ],
                "/admin/evaluations",
                vec![],
            ))
            .build(),
        // ── Policy Studio — shared page
        // constructors; the guard guarantees `Some` ( dispatch).
        p if sentin8::rfw::policy_page("sentin8:ai", p).is_some() => {
            sentin8::rfw::policy_page("sentin8:ai", p)
                .expect("policy_page checked in guard")
                .build()
        }
        other => {
            return Err((StatusCode::NOT_FOUND, format!("no admin page '{other}'")));
        }
    };
    Ok(Json(
        serde_json::to_value(AdminUiResponse::Page { page: def }).unwrap_or_default(),
    ))
}

/// `GET /v1/admin/{resource}` — RFW data endpoint (env-scoped, RLS on the
/// same connection; `target_env_id` REQUIRED — Fix A).
#[utoipa::path(
    get,
    operation_id = "ai.admin.data",
    path = "/v1/admin/{resource}",
    params(("resource" = String, Path), ("target_env_id" = String, Query)),
    responses((status = 200, description = "Admin data rows")),
    tag = "ai",
)]
pub async fn get_admin_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(resource): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:ai:prompt:read"),
    )
    .await?;
    let env_id = q
        .target_env_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "missing target_env_id — must specify the env to administer".to_string(),
            )
        })?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(crate::handlers::err_db_pub)?;
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *conn)
        .await
        .map_err(crate::handlers::err_db_pub)?;
    let rows: Vec<serde_json::Value> = match resource.as_str() {
        "prompts" => {
            sqlx::query("SELECT name, version, model_primary, status, origin FROM ai.prompts WHERE env_id = $1 ORDER BY name, version DESC LIMIT 100")
                .bind(env_id)
                .fetch_all(&mut *conn)
                .await
                .map_err(crate::handlers::err_db_pub)?
                .iter()
                .map(|r| serde_json::json!({
                    "name": r.get::<String, _>("name"),
                    "version": r.get::<i32, _>("version"),
                    "model_primary": r.get::<String, _>("model_primary"),
                    "status": r.get::<String, _>("status"),
                    "origin": r.get::<String, _>("origin"),
                }))
                .collect()
        }
        "providers" => {
            sqlx::query("SELECT provider, base_url, credential_ref, status FROM ai.providers WHERE env_id = $1 ORDER BY provider")
                .bind(env_id)
                .fetch_all(&mut *conn)
                .await
                .map_err(crate::handlers::err_db_pub)?
                .iter()
                .map(|r| serde_json::json!({
                    "provider": r.get::<String, _>("provider"),
                    "base_url": r.get::<String, _>("base_url"),
                    "credential_ref": r.get::<String, _>("credential_ref"),
                    "status": r.get::<String, _>("status"),
                }))
                .collect()
        }
        "traces" => {
            sqlx::query("SELECT prompt_name, model, feature, input_tokens, output_tokens, latency_ms, cache_hit FROM ai.traces WHERE env_id = $1 ORDER BY created_at DESC LIMIT 100")
                .bind(env_id)
                .fetch_all(&mut *conn)
                .await
                .map_err(crate::handlers::err_db_pub)?
                .iter()
                .map(|r| serde_json::json!({
                    "prompt_name": r.get::<String, _>("prompt_name"),
                    "model": r.get::<String, _>("model"),
                    "feature": r.get::<String, _>("feature"),
                    "input_tokens": r.get::<i64, _>("input_tokens"),
                    "output_tokens": r.get::<i64, _>("output_tokens"),
                    "latency_ms": r.get::<i32, _>("latency_ms"),
                    "cache_hit": r.get::<bool, _>("cache_hit"),
                }))
                .collect()
        }
        "budgets" => {
            sqlx::query("SELECT feature, monthly_token_cap, enforcement, status FROM ai.budgets WHERE env_id = $1 ORDER BY feature")
                .bind(env_id)
                .fetch_all(&mut *conn)
                .await
                .map_err(crate::handlers::err_db_pub)?
                .iter()
                .map(|r| serde_json::json!({
                    "feature": r.get::<String, _>("feature"),
                    "monthly_token_cap": r.get::<i64, _>("monthly_token_cap"),
                    "enforcement": r.get::<String, _>("enforcement"),
                    "status": r.get::<String, _>("status"),
                }))
                .collect()
        }
        "dlq" => {
            sqlx::query("SELECT job_type, error_message, retry_count FROM ai.dlq WHERE env_id = $1 ORDER BY created_at DESC LIMIT 100")
                .bind(env_id)
                .fetch_all(&mut *conn)
                .await
                .map_err(crate::handlers::err_db_pub)?
                .iter()
                .map(|r| serde_json::json!({
                    "job_type": r.get::<String, _>("job_type"),
                    "error_message": r.get::<String, _>("error_message"),
                    "retry_count": r.get::<i32, _>("retry_count"),
                }))
                .collect()
        }
        "evaluations" => {
            sqlx::query("SELECT prompt_name, prompt_version, status, score::text AS score, cases_passed, cases_total FROM ai.evaluations WHERE env_id = $1 ORDER BY created_at DESC LIMIT 100")
                .bind(env_id)
                .fetch_all(&mut *conn)
                .await
                .map_err(crate::handlers::err_db_pub)?
                .iter()
                .map(|r| serde_json::json!({
                    "prompt_name": r.get::<String, _>("prompt_name"),
                    "prompt_version": r.get::<i32, _>("prompt_version"),
                    "status": r.get::<String, _>("status"),
                    "score": r.get::<Option<String>, _>("score").unwrap_or_default(),
                    "cases_passed": r.get::<i32, _>("cases_passed"),
                    "cases_total": r.get::<i32, _>("cases_total"),
                }))
                .collect()
        }
        _ => vec![],
    };
    Ok(Json(serde_json::Value::Array(rows)))
}

// ── Widget helpers (cron/func pattern) ─────────────────────────────────────

fn field_text(key: &str, label: &str, required: bool) -> WidgetFormField {
    WidgetFormField {
        key: key.into(),
        label: label.into(),
        field_type: FormFieldType::Text,
        required,
        placeholder: None,
        default_value: None,
        options: None,
        validation: None,
        width: None,
        help_text: None,
        visible_if: None,
    }
}

fn field_number(key: &str, label: &str, required: bool) -> WidgetFormField {
    WidgetFormField {
        field_type: FormFieldType::Number,
        ..field_text(key, label, required)
    }
}

fn field_textarea(key: &str, label: &str, required: bool) -> WidgetFormField {
    WidgetFormField {
        field_type: FormFieldType::Textarea,
        ..field_text(key, label, required)
    }
}

fn select_field(key: &str, label: &str, options: Vec<(&str, &str)>) -> WidgetFormField {
    WidgetFormField {
        key: key.into(),
        label: label.into(),
        field_type: FormFieldType::Select,
        required: true,
        placeholder: None,
        default_value: None,
        options: Some(
            options
                .into_iter()
                .map(|(v, l)| FormFieldOption {
                    value: v.into(),
                    label: l.into(),
                })
                .collect(),
        ),
        validation: None,
        width: None,
        help_text: None,
        visible_if: None,
    }
}

fn cols(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: true,
        width: None,
        format: None,
    }
}

fn table_with_actions(
    columns: Vec<WidgetDataTableColumn>,
    endpoint: &str,
    row_actions: Vec<WidgetButton>,
) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions,
    })
}

fn row_action_post(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Primary,
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}

fn link(label: &str, route: &str) -> AdminUiAction {
    AdminUiAction {
        label: label.into(),
        action_type: AdminUiActionType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: Some("add".into()),
    }
}
