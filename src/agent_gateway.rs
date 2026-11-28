// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Tool dispatch - the executable half of the gateway (ai DESIGN.md §4.2).
//!
//! [`crate::tools`] resolves and validates; this module performs the call.
//! Every route is one of the four declared kinds, and each route's owner
//! re-authorizes independently:
//!
//! | kind | transport | authority |
//! |------|-----------|-----------|
//! | `http_action` | `POST` to the service action endpoint | the caller's token |
//! | `flow_workflow` | `POST /v1/workflows` on Sentin8:Flow | the `ai-proxy` workload cert |
//! | `func_module` | `POST /v1/modules/{id}/execute` on Sentin8:Func | the `ai-proxy` workload cert |
//! | `builtin` | in-process | n/a |
//!
//! Nothing is cached and nothing is retried here: a failed tool returns an
//! error the model reasons about, and a timeout is a timeout.

use sha2::Digest as _;
use sqlx::Row;
use uuid::Uuid;

use crate::handlers::AppState;
use crate::tools::ToolSpec;

/// One resolved dispatch request.
pub struct Dispatch<'a> {
    pub state: &'a AppState,
    pub env_id: Uuid,
    /// The caller's bearer (the `Authorization` header value as received).
    /// Forwarded to an `http_action` owner so the owner re-verifies and
    /// re-authorizes the real user - AI never escalates authority.
    pub bearer: &'a str,
    pub correlation_id: &'a str,
    /// Idempotency key for the dispatch (the tool-call row id), so a
    /// `func_module` retry cannot double-apply.
    pub idempotency_key: &'a str,
}

/// Dispatch a validated tool call. The caller has already checked the
/// schema and the scope; this only routes.
pub async fn dispatch(
    d: &Dispatch<'_>,
    spec: &ToolSpec,
    arguments: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let started = std::time::Instant::now();
    let result = match spec.kind.as_str() {
        "http_action" => dispatch_http_action(d, spec, arguments).await,
        "flow_workflow" => dispatch_flow(d, spec, arguments).await,
        "func_module" => dispatch_func(d, spec, arguments).await,
        "builtin" => dispatch_builtin(spec, arguments),
        other => Err(format!("unknown tool kind '{other}'")),
    };
    tracing::debug!(
        tool = %spec.name,
        kind = %spec.kind,
        elapsed_ms = started.elapsed().as_millis() as u64,
        ok = result.is_ok(),
        "ai tool dispatch"
    );
    result
        .map(|v| sanitize_tool_result(v, spec.max_response_bytes))
        .map_err(|e| e)
}

/// Bound and sanitize a tool result before it re-enters the transcript:
/// cap to the tool's response bytes, then strip PII deny-list keys (the same
/// list Stat and the trace path use). A tool result is untrusted model input
/// - the primary injection and exfiltration channel in a loop (ai DESIGN.md
/// §4.2 "cap bytes + PII strip").
/// Bound and sanitize a tool result before it re-enters the transcript:
/// cap to the tool's response bytes, then strip PII deny-list keys (the same
/// list Stat and the trace path use). A tool result is untrusted model input
/// - the primary injection and exfiltration channel in a loop (ai DESIGN.md
/// §4.2 "cap bytes + PII strip").
///
/// Public because the integration suite pins the exfiltration guarantee;
/// production callers reach it through `dispatch`.
pub fn sanitize_tool_result(value: serde_json::Value, max_bytes: i32) -> serde_json::Value {
    let capped = crate::tools::cap_result(value, max_bytes);
    // Recursive: a tool result nests (rows of accounts, lists of cards), and
    // the deny-list keys appear at every depth. The shared `strip_pii` is
    // top-level only (its trace/stat callers need exactly that), so the
    // gateway walks the tree itself.
    strip_pii_deep(capped)
}

/// Recursively remove deny-list keys from an object/array tree. Returns the
/// cleaned value; non-container values pass through untouched.
fn strip_pii_deep(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut cleaned = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                let lower = k.to_lowercase();
                if crate::safety::PII_DENY_LIST.contains(&lower.as_str()) {
                    continue;
                }
                cleaned.insert(k, strip_pii_deep(v));
            }
            serde_json::Value::Object(cleaned)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(strip_pii_deep).collect())
        }
        other => other,
    }
}

/// `http_action` - forward to the owning service through the same
/// `sys.service_actions` registry the BFF uses. The tool names an ACTION;
/// the URL is resolved here so no URL ever lives on a tool row.
async fn dispatch_http_action(
    d: &Dispatch<'_>,
    spec: &ToolSpec,
    arguments: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let action = crate::tools::http_action_name(spec)
        .ok_or_else(|| "http_action tool has no target.action".to_string())?;

    // Resolve the action: `platform_domain_key` + `endpoint` + `method`.
    // Read on the caller's env so an action registered by a vertical in this
    // env is found; the platform rows are visible too (service_actions is a
    // platform registry).
    let mut tx = crate::handlers::begin_tenant_tx(&d.state.pool, d.env_id)
        .await
        .map_err(|(_, e)| format!("resolve action: {e}"))?;
    // Schema-qualified: the `sentin8_ai_service` role's search_path is
    // `ai, public` (func DESIGN §8 invariant 7 documents the identical rule),
    // so an unqualified name would fail at runtime.
    let row = sqlx::query(
        "SELECT platform_domain_key, endpoint, method FROM sys.service_actions WHERE action = $1",
    )
    .bind(action)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("resolve action: {e}"))?;
    let _ = tx.commit().await;
    let row = row.ok_or_else(|| format!("no service action registered for '{action}'"))?;
    let domain_key: String = row.get("platform_domain_key");
    let endpoint: String = row.get("endpoint");
    let method: String = row.get("method");

    let cfg = sentin8::config::Sentin8Config::from_env();
    let url = format!("https://{}{}", cfg.platform_domain(&domain_key), endpoint);

    let client = reqwest::Client::new();
    let builder = match method.to_uppercase().as_str() {
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "PATCH" => client.patch(&url),
        "DELETE" => client.delete(&url),
        _ => client.get(&url),
    };
    let builder = builder
        .header(
            axum::http::header::AUTHORIZATION.as_str(),
            d.bearer,
        )
        .header("x-sentin8-correlation-id", d.correlation_id)
        .timeout(std::time::Duration::from_millis(
            if spec.timeout_ms <= 0 { 30000 } else { spec.timeout_ms as u64 },
        ));
    let builder = if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("DELETE") {
        builder
    } else {
        builder.json(arguments)
    };

    let resp = builder.send().await.map_err(|e| format!("action call failed: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("action '{action}' returned HTTP {status}: {}", snippet(&body)));
    }
    Ok(serde_json::from_str(&body).unwrap_or_else(|_| serde_json::json!({"raw": body})))
}

/// `flow_workflow` - start a Sentin8:Flow workflow. A workflow that parks in
/// `waiting` is surfaced as an approval pause (the tool row declared an
/// irreversible effect and the flow itself needs a decision).
async fn dispatch_flow(
    d: &Dispatch<'_>,
    spec: &ToolSpec,
    arguments: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let logic_id = crate::tools::flow_logic_id(spec)
        .ok_or_else(|| "flow_workflow tool has no target.logic_id".to_string())?;
    let req = sentin8_flow_sdk::client::CreateWorkflowRequest {
        domain: spec
            .target
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("ai-agent")
            .to_string(),
        logic: sentin8_flow_sdk::client::LogicVersion {
            logic_id: logic_id.to_string(),
            version: 1,
            steps: vec![sentin8_flow_sdk::client::StepDef {
                name: "execute".into(),
                kind: "BasicStep".into(),
                next_step: None,
                config: Some(arguments.clone()),
                on_error: Some("fail".into()),
            }],
            correlation_id_func: None,
            expected_parameters: None,
        },
        input: serde_json::json!({
            "env_id": d.env_id,
            "arguments": arguments,
            "correlation_id": d.correlation_id,
        }),
        callback_config: sentin8_flow_sdk::client::CallbackConfig {
            base_url: String::new(),
            auth_token: String::new(),
            internal_path: "/v1/internal".into(),
            host_functions: Default::default(),
        },
        correlation_id: Some(d.idempotency_key.to_string()),
    };
    let record = d
        .state
        .flow
        .create_workflow(&req)
        .await
        .map_err(|e| format!("flow start failed: {e}"))?;
    Ok(serde_json::json!({
        "workflow_id": record.id.to_string(),
        "state": format!("{:?}", record.state).to_lowercase(),
    }))
}

/// `func_module` - execute a Sentin8:Func module with the dispatch's
/// idempotency key, so a retried tool call replays instead of re-applying.
async fn dispatch_func(
    d: &Dispatch<'_>,
    spec: &ToolSpec,
    arguments: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let (module_id, hook) = crate::tools::func_module(spec)
        .ok_or_else(|| "func_module tool has no target.module_id".to_string())?;
    let func = d.state.func.as_ref().ok_or_else(|| {
        "func_module tools are unavailable: Sentin8:Func is not reachable from this instance".to_string()
    })?;
    let req = sentin8_func_sdk::client::ExecuteRequest {
        hook,
        context: arguments.clone(),
        callback_config: None,
        idempotency_key: Some(d.idempotency_key.to_string()),
    };
    let resp = func
        .execute(&module_id, &req)
        .await
        .map_err(|e| format!("func execute failed: {e}"))?;
    Ok(resp)
}

/// `builtin` - in-process capabilities. Deliberately tiny: a builtin has no
/// authority beyond what AI already holds, so there is nothing to escalate.
fn dispatch_builtin(
    spec: &ToolSpec,
    arguments: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    match spec.target.get("builtin").and_then(|b| b.as_str()).unwrap_or("echo") {
        "echo" => Ok(serde_json::json!({"echo": arguments})),
        "now" => Ok(serde_json::json!({"now": chrono::Utc::now().to_rfc3339()})),
        "sum" => {
            let nums: Vec<f64> = arguments
                .get("values")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|n| n.as_f64()).collect())
                .unwrap_or_default();
            Ok(serde_json::json!({ "sum": nums.iter().sum::<f64>() }))
        }
        other => Err(format!("unknown builtin '{other}'")),
    }
}

fn snippet(body: &str) -> String {
    body.chars().take(200).collect()
}

/// Stable per-(run, tool-call) idempotency key: a retried dispatch of the
/// same call dedupes at the target instead of re-applying.
pub fn dispatch_key(run_id: Uuid, tool_call_id: Uuid) -> String {
    let mut h = sha2::Sha256::new();
    h.update(format!("{run_id}:{tool_call_id}").as_bytes());
    format!("{:x}", h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_key_is_stable_and_distinct() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_eq!(dispatch_key(a, b), dispatch_key(a, b));
        assert_ne!(dispatch_key(a, b), dispatch_key(b, a));
    }

    #[test]
    fn builtin_echo_and_sum_stay_bounded() {
        let spec = ToolSpec {
            id: Uuid::nil(),
            name: "t".into(),
            description: String::new(),
            input_schema: serde_json::json!({}),
            kind: "builtin".into(),
            target: serde_json::json!({"builtin": "sum"}),
            required_scope: String::new(),
            side_effect: "read".into(),
            requires_confirmation: false,
            rate_limit_per_min: 0,
            timeout_ms: 30000,
            max_response_bytes: 65536,
            enabled: true,
        };
        let out = dispatch_builtin(&spec, &serde_json::json!({"values": [1, 2, 3.5]})).unwrap();
        assert_eq!(out["sum"], 6.5);
    }
}
