// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Controlled agent runtime.
//!
//! The model emits **intent** — never executes. An agent request resolves
//! the prompt's tool allowlist, runs inference to obtain a structured
//! intent, then maps the intent to a Sentin8:Flow workflow whose domain
//! steps proxy-back to the owning service (the exact Func/Flow/Cron
//! proxy-back pattern). `requires_confirmation` intents pause in a
//! `ManualDecisionStep`; approval applies the caller's authorization at
//! execution time.
//!
//! Audit: every executed agent action emits a best-effort Sentin8:Audit
//! event preserving the `act` chain (user → agent → domain service).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Structured intent emitted by the model. The model has NO
/// execution surface — this contract is the only output shape accepted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
pub struct AgentIntent {
    pub action: String,
    #[serde(default)]
    pub params: serde_json::Value,
    #[serde(default)]
    pub requires_confirmation: bool,
}

/// Parse the model output into an intent. The content must be exactly one
/// JSON object conforming to [`AgentIntent`] — anything else is rejected
/// (fail-closed: no free-text execution).
pub fn parse_intent(content: &str) -> Result<AgentIntent, String> {
    let trimmed = content.trim();
    // Strip a markdown code fence if the model wrapped the JSON.
    let json_str = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .map(|s| s.trim())
        .and_then(|s| s.strip_suffix("```"))
        .map(|s| s.trim())
        .unwrap_or(trimmed);
    let intent: AgentIntent = serde_json::from_str(json_str)
        .map_err(|e| format!("model output is not a valid intent: {e}"))?;
    if intent.action.trim().is_empty() {
        return Err("intent action is empty".into());
    }
    Ok(intent)
}

/// A declared tool: the action name the model may emit, the Sentin8:Flow
/// logic that executes it, and whether human confirmation is mandatory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDecl {
    pub action: String,
    /// Flow logic_id registered for this tool.
    pub flow_logic_id: String,
    #[serde(default)]
    pub requires_confirmation: bool,
}

/// Map a parsed intent to its allowed tool declaration. The
/// allowlist comes from the prompt's `tools` array; unknown actions are
/// rejected before any workflow is created.
pub fn resolve_tool<'a>(
    allowed: &'a [ToolDecl],
    intent: &AgentIntent,
) -> Result<&'a ToolDecl, String> {
    allowed
        .iter()
        .find(|t| t.action == intent.action)
        .ok_or_else(|| {
            format!(
                "action '{}' is not in the prompt's tool allowlist",
                intent.action
            )
        })
}

/// Build the Sentin8:Flow workflow request for an allowed intent.
/// Agent tasks ARE Flow workflows — resume/repair semantics come free, no
/// new state store.
pub fn agent_workflow_request(
    tool: &ToolDecl,
    intent: &AgentIntent,
    env_id: Uuid,
    subject_id: &str,
    correlation_id: &str,
) -> sentin8_flow_sdk::client::CreateWorkflowRequest {
    // The step plan: intent → ManualDecisionStep (when confirmation) → the
    // domain step that proxy-calls back to the owning service.
    let mut steps = Vec::new();
    if intent.requires_confirmation || tool.requires_confirmation {
        steps.push(sentin8_flow_sdk::client::StepDef {
            name: "await_confirmation".into(),
            kind: "ManualDecisionStep".into(),
            next_step: Some("execute".into()),
            config: Some(serde_json::json!({
                "prompt": format!("Approve agent action '{}'?", intent.action),
            })),
            on_error: None,
        });
    }
    steps.push(sentin8_flow_sdk::client::StepDef {
        name: "execute".into(),
        kind: "BasicStep".into(),
        next_step: None,
        config: Some(serde_json::json!({
            "action": intent.action,
            "params": intent.params,
        })),
        on_error: Some("fail".into()),
    });
    sentin8_flow_sdk::client::CreateWorkflowRequest {
        domain: "ai-agent".into(),
        logic: sentin8_flow_sdk::client::LogicVersion {
            logic_id: tool.flow_logic_id.clone(),
            version: 1,
            steps,
            correlation_id_func: None,
            expected_parameters: None,
        },
        input: serde_json::json!({
            "env_id": env_id,
            "subject_id": subject_id,
            "action": intent.action,
            "params": intent.params,
        }),
        callback_config: sentin8_flow_sdk::client::CallbackConfig {
            // Proxy-back target: the AI service itself resolves the tool's
            // owning service and forwards the authorized action.
            base_url: String::new(),   // filled by the caller from config
            auth_token: String::new(), // the ticker/host uses a fresh M2M token
            internal_path: "/v1/internal".into(),
            host_functions: Default::default(),
        },
        correlation_id: Some(correlation_id.to_string()),
    }
}

/// Best-effort audit event for an executed agent action — the
/// func-service pattern: direct insert with tenant context on the same
/// connection, never blocks the response path.
pub async fn audit_agent_action(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    subject_id: &str,
    action: &str,
    workflow_id: Option<&str>,
    details: serde_json::Value,
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
    .bind("agent.execute")
    .bind(serde_json::json!({
        "action": "agent.execute",
        "agent_action": action,
        "subject_id": subject_id,
        "workflow_id": workflow_id,
        "details": details,
        "act_chain": ["user", "agent", "domain-service"],
    }))
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_intent_accepts_plain_and_fenced_json() {
        let a = parse_intent(
            r#"{"action":"cancel_subscription","params":{"id":"1"},"requires_confirmation":true}"#,
        )
        .unwrap();
        assert_eq!(a.action, "cancel_subscription");
        let b = parse_intent("```json\n{\"action\":\"lookup\",\"params\":{}}\n```").unwrap();
        assert_eq!(b.action, "lookup");
        // Free text is rejected — the model cannot smuggle instructions.
        assert!(parse_intent("I will now cancel the subscription").is_err());
        assert!(parse_intent("{\"action\":\"\"}").is_err());
    }

    #[test]
    fn resolve_tool_rejects_unknown_action() {
        let allowed = vec![ToolDecl {
            action: "lookup_customer".into(),
            flow_logic_id: "lookup".into(),
            requires_confirmation: false,
        }];
        let intent = AgentIntent {
            action: "drop_database".into(),
            params: serde_json::json!({}),
            requires_confirmation: false,
        };
        assert!(resolve_tool(&allowed, &intent).is_err());
    }

    #[test]
    fn confirmation_inserts_manual_decision_step() {
        let tool = ToolDecl {
            action: "cancel_subscription".into(),
            flow_logic_id: "cancel-sub".into(),
            requires_confirmation: false,
        };
        let intent = AgentIntent {
            action: "cancel_subscription".into(),
            params: serde_json::json!({"id": "1"}),
            requires_confirmation: true,
        };
        let req = agent_workflow_request(&tool, &intent, uuid::Uuid::new_v4(), "sub", "corr");
        let kinds: Vec<&str> = req.logic.steps.iter().map(|s| s.kind.as_str()).collect();
        assert_eq!(kinds, vec!["ManualDecisionStep", "BasicStep"]);

        let no_confirm = AgentIntent {
            action: "cancel_subscription".into(),
            params: serde_json::json!({"id": "1"}),
            requires_confirmation: false,
        };
        let req2 = agent_workflow_request(&tool, &no_confirm, uuid::Uuid::new_v4(), "sub", "corr");
        assert_eq!(
            req2.logic.steps.len(),
            1,
            "no confirmation → straight execution"
        );
    }
}
