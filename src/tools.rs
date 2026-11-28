// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:AI
// SPDX-License-Identifier: Apache-2.0

//! Tool gateway - the single dispatch path from model output to a side
//! effect (ai DESIGN.md §4.2).
//!
//! A tool is a tenant-authored ROW (`ai.tools`), not a code path. Dispatch is
//! uniform: JSON-Schema validate the arguments, apply the rate limit, check
//! the caller's live scopes against `required_scope`, then route by `kind`:
//!
//! - `http_action` - resolve through `sys.service_actions` (the same registry
//!   the BFF's `/bff/action/{action}` uses) and forward with the caller's
//!   token. No URL is ever stored on a tool row.
//! - `flow_workflow` - create a Sentin8:Flow workflow; a `Waiting` state maps
//!   to an approval pause.
//! - `func_module` - execute a Sentin8:Func module with an idempotency key.
//! - `builtin` - in-process (clock, arithmetic) - no external effect.
//!
//! Denials are model-visible facts: the refusal reason is returned so the
//! model can adapt, and it is journalled with the same reason. Nothing here
//! retries, and nothing here escalates authority - the caller's token rides
//! every dispatch.

use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use sqlx::Row;
use uuid::Uuid;

/// A tool row resolved for one dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub kind: String,
    pub target: serde_json::Value,
    pub required_scope: String,
    pub side_effect: String,
    pub requires_confirmation: bool,
    pub rate_limit_per_min: i32,
    pub timeout_ms: i32,
    pub max_response_bytes: i32,
    pub enabled: bool,
}

impl ToolSpec {
    /// Whether this tool must pause for human approval before dispatch.
    pub fn needs_approval(&self) -> bool {
        self.requires_confirmation || self.side_effect == "irreversible"
    }

    /// The model-facing tool definition (JSON Schema function object), so a
    /// provider can be given exactly the tools the caller is allowed to use.
    pub fn definition(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.input_schema,
            }
        })
    }
}

/// Outcome of a gateway dispatch.
#[derive(Debug, Clone)]
pub enum DispatchOutcome {
    /// The tool ran; `result` is the bounded, PII-filtered payload the model
    /// will see.
    Ok { result: serde_json::Value, duration_ms: u64 },
    /// The tool ran and failed - the model sees the error and can adapt.
    Error { message: String, duration_ms: u64 },
    /// The call was refused (schema, scope, not found, rate limit).
    Denied { reason: String },
    /// An irreversible action paused for approval.
    AwaitingApproval { approval_id: Uuid },
}

/// Validate arguments against a JSON Schema subset (type/properties/required/
/// additionalProperties). A full JSON Schema engine is not needed for tool
/// arguments, and a hand-rolled check keeps the trust boundary explicit: the
/// gateway MUST reject anything it cannot positively validate.
pub fn validate_arguments(schema: &serde_json::Value, args: &serde_json::Value) -> Result<(), String> {
    // A tool with no declared schema accepts any object (tenants may omit it).
    let Some(obj_schema) = schema.as_object() else {
        return Ok(());
    };
    let schema_type = obj_schema.get("type").and_then(|t| t.as_str());
    if let Some(t) = schema_type {
        let actual = match args {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "boolean",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
        };
        // JSON Schema allows integer to satisfy "number".
        let ok = t == actual || (t == "number" && actual == "number") || (t == "integer" && actual == "number");
        if !ok {
            return Err(format!("expected {t}, got {actual}"));
        }
    }

    if schema_type == Some("object") {
        let Some(args_obj) = args.as_object() else {
            return Err(format!("expected object, got {}", type_name(args)));
        };
        // Required members must be present.
        if let Some(required) = obj_schema.get("required").and_then(|r| r.as_array()) {
            for r in required {
                if let Some(name) = r.as_str() {
                    if !args_obj.contains_key(name) {
                        return Err(format!("missing required argument '{name}'"));
                    }
                }
            }
        }
        // Declared properties: check their type when a value is present.
        if let Some(props) = obj_schema.get("properties").and_then(|p| p.as_object()) {
            for (name, prop_schema) in props {
                if let Some(value) = args_obj.get(name) {
                    validate_arguments(prop_schema, value)
                        .map_err(|e| format!("argument '{name}': {e}"))?;
                }
            }
            // additionalProperties: false ⇒ reject undeclared members.
            if obj_schema.get("additionalProperties") == Some(&serde_json::Value::Bool(false)) {
                for key in args_obj.keys() {
                    if !props.contains_key(key) {
                        return Err(format!("unexpected argument '{key}'"));
                    }
                }
            }
        }
    }

    if schema_type == Some("array") {
        let Some(items) = args.as_array() else {
            return Err(format!("expected array, got {}", type_name(args)));
        };
        if let Some(item_schema) = obj_schema.get("items") {
            for (i, item) in items.iter().enumerate() {
                validate_arguments(item_schema, item).map_err(|e| format!("item {i}: {e}"))?;
            }
        }
    }

    Ok(())
}

fn type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Canonical hash of the arguments, journalled so a mutation is provable
/// after the fact without replaying the model.
pub fn arguments_hash(args: &serde_json::Value) -> String {
    let mut hasher = sha2::Sha256::new();
    // Canonicalise first: `serde_json::Map` preserves insertion order, so a
    // model that emits `{a,b}` in one turn and `{b,a}` in another would hash
    // differently for the same logical arguments. Sorting keys makes the hash
    // an identity for the argument SET, which is what audit needs.
    hasher.update(canonical_json(args).as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Serialise JSON with object keys sorted recursively, so equal objects always
/// produce the same bytes regardless of key insertion order.
fn canonical_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String((*k).clone()).to_string());
                out.push(':');
                out.push_str(&canonical_json(&map[*k]));
            }
            out.push('}');
            out
        }
        serde_json::Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        other => other.to_string(),
    }
}

/// Load the tools bound to an agent, filtered by the caller's scopes.
///
/// `ai.tools` is the catalogue; `ai.agent_tools` is the binding. A tool whose
/// `required_scope` the caller does not hold is EXCLUDED from the definition
/// list - the model is never offered a tool the caller cannot use, which
/// prevents both wasted turns and a leaked capability name.
pub async fn load_agent_tools(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    env_id: Uuid,
    agent_id: Uuid,
    scopes: &[String],
) -> Result<Vec<ToolSpec>, String> {
    let rows = sqlx::query(
        "SELECT t.id, t.name, t.description, t.input_schema, t.kind, t.target, \
                t.required_scope, t.side_effect, t.requires_confirmation, \
                t.rate_limit_per_min, t.timeout_ms, t.max_response_bytes, t.enabled \
           FROM ai.tools t \
           JOIN ai.agent_tools at ON at.tool_id = t.id AND at.enabled = true \
          WHERE at.agent_id = $1 AND t.env_id = $2 AND t.enabled = true \
          ORDER BY t.name",
    )
    .bind(agent_id)
    .bind(env_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("load tools: {e}"))?;

    Ok(rows
        .iter()
        .map(|r| ToolSpec {
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
        .filter(|t| scope_admits(scopes, &t.required_scope))
        .collect())
}

/// Whether the caller's live scope set satisfies a tool's required scope.
/// An empty requirement is satisfied by any authenticated caller - the
/// `builtin` tools use that.
pub fn scope_admits(scopes: &[String], required: &str) -> bool {
    if required.trim().is_empty() {
        return true;
    }
    scopes.iter().any(|s| s == required)
}

/// Load one tool by name in the caller's env (used at dispatch time - the
/// definition list is a snapshot, the row is authoritative).
pub async fn load_tool(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    env_id: Uuid,
    name: &str,
) -> Result<Option<ToolSpec>, String> {
    let row = sqlx::query(
        "SELECT id, name, description, input_schema, kind, target, required_scope, \
                side_effect, requires_confirmation, rate_limit_per_min, timeout_ms, \
                max_response_bytes, enabled \
           FROM ai.tools WHERE env_id = $1 AND name = $2",
    )
    .bind(env_id)
    .bind(name)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| format!("load tool: {e}"))?;
    Ok(row.map(|r| ToolSpec {
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
    }))
}

/// The `target` reference for an `http_action` tool: a `sys.service_actions`
/// action name. Resolution happens in [`crate::agent_gateway`].
pub fn http_action_name(spec: &ToolSpec) -> Option<&str> {
    spec.target.get("action").and_then(|a| a.as_str())
}

/// The `logic_id` for a `flow_workflow` tool.
pub fn flow_logic_id(spec: &ToolSpec) -> Option<&str> {
    spec.target.get("logic_id").and_then(|l| l.as_str())
}

/// The `(module_id, hook)` for a `func_module` tool.
pub fn func_module(spec: &ToolSpec) -> Option<(String, String)> {
    let module = spec.target.get("module_id").and_then(|m| m.as_str())?;
    let hook = spec
        .target
        .get("hook")
        .and_then(|h| h.as_str())
        .unwrap_or("scheduled_event");
    Some((module.to_string(), hook.to_string()))
}

/// Truncate a tool result to the tool's response cap. A tool returning a
/// large payload cannot bloat the transcript or the next provider call.
pub fn cap_result(value: serde_json::Value, max_bytes: i32) -> serde_json::Value {
    let cap = if max_bytes <= 0 { 65536 } else { max_bytes as usize };
    let rendered = value.to_string();
    if rendered.len() <= cap {
        return value;
    }
    // Budget for the head so the wrapper (marker + JSON overhead) also stays
    // under the cap - a truncated result must not exceed the cap it enforces.
    let head_budget = cap.saturating_sub(64).max(16);
    let head: String = rendered.chars().take(head_budget).collect();
    serde_json::json!({
        "__truncated": true,
        "__head": head,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_rejects_missing_required_and_wrong_type() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "account": {"type": "string"},
                "amount": {"type": "number"},
            },
            "required": ["account"],
            "additionalProperties": false,
        });
        assert!(validate_arguments(&schema, &serde_json::json!({"account": "a1", "amount": 5})).is_ok());
        assert!(validate_arguments(&schema, &serde_json::json!({"amount": 5})).is_err());
        assert!(validate_arguments(&schema, &serde_json::json!({"account": 7})).is_err());
        assert!(validate_arguments(&schema, &serde_json::json!({"account": "a", "extra": 1})).is_err());
    }

    #[test]
    fn schema_rejects_free_text_arguments() {
        let schema = serde_json::json!({"type": "object", "properties": {}});
        // A model that emitted prose instead of an object must be denied.
        assert!(validate_arguments(&schema, &serde_json::json!("please delete it")).is_err());
        assert!(validate_arguments(&schema, &serde_json::Value::Null).is_err());
    }

    #[test]
    fn empty_scope_requirement_is_open_but_named_scope_is_not() {
        let scopes = vec!["sentin8:ai:agent:run".to_string()];
        assert!(scope_admits(&scopes, ""));
        assert!(!scope_admits(&scopes, "bank8:ledger:account:write"));
        let owner = vec!["bank8:ledger:account:write".to_string()];
        assert!(scope_admits(&owner, "bank8:ledger:account:write"));
    }

    #[test]
    fn arguments_hash_is_stable_and_order_independent() {
        let a = serde_json::json!({"x": 1, "y": "b"});
        let b = serde_json::json!({"y": "b", "x": 1});
        assert_eq!(arguments_hash(&a), arguments_hash(&b));
        assert_ne!(arguments_hash(&a), arguments_hash(&serde_json::json!({"x": 2})));
    }

    #[test]
    fn cap_result_truncates_and_marks() {
        let big = serde_json::json!({"rows": "x".repeat(1000)});
        let capped = cap_result(big, 100);
        assert_eq!(capped.get("__truncated"), Some(&serde_json::Value::Bool(true)));
        assert!(capped.to_string().len() < 1000);
    }

    #[test]
    fn side_effect_decides_approval() {
        let mut spec = ToolSpec {
            id: Uuid::nil(),
            name: "t".into(),
            description: String::new(),
            input_schema: serde_json::json!({}),
            kind: "builtin".into(),
            target: serde_json::json!({}),
            required_scope: String::new(),
            side_effect: "read".into(),
            requires_confirmation: false,
            rate_limit_per_min: 0,
            timeout_ms: 30000,
            max_response_bytes: 65536,
            enabled: true,
        };
        assert!(!spec.needs_approval());
        spec.side_effect = "irreversible".into();
        assert!(spec.needs_approval());
        spec.side_effect = "read".into();
        spec.requires_confirmation = true;
        assert!(spec.needs_approval());
    }
}
